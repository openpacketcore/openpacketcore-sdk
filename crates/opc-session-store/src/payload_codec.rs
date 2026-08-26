//! Product-owned session payload envelope and codec helpers.
//!
//! The session store deliberately keeps product DTOs outside the SDK, but
//! packet-core products still need one shared wrapper for format identity,
//! schema version, strict decode checks, and backend size validation before a
//! plaintext payload is sealed by [`crate::EncryptingSessionBackend`].

use std::fmt;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

use crate::{BackendCapabilities, EncryptedSessionPayload};

const MAX_FORMAT_LEN: usize = 128;
const MAX_CONTENT_TYPE_LEN: usize = 128;

/// Content type used by [`encode_json_payload`] for the product-owned body.
pub const SESSION_PAYLOAD_JSON_CONTENT_TYPE: &str = "application/json";

/// Validated product-owned session payload format name.
///
/// Format names are deployment-visible schema identifiers, not product state.
/// They must be stable ASCII tokens so they are safe to persist and compare
/// across SDK versions.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionPayloadFormat(String);

impl SessionPayloadFormat {
    /// Validate and construct a payload format name.
    ///
    /// Accepts non-empty ASCII identifiers up to 128 bytes containing
    /// alphanumeric characters plus `.`, `_`, `-`, and `/`.
    pub fn new(value: impl Into<String>) -> Result<Self, SessionPayloadCodecError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_FORMAT_LEN
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/')
            })
        {
            return Err(SessionPayloadCodecError::InvalidFormat);
        }

        Ok(Self(value))
    }

    /// Create a format name from a known-valid static string.
    ///
    /// # Panics
    ///
    /// Panics if `value` is not accepted by [`Self::new`].
    pub fn from_static(value: &'static str) -> Self {
        Self::new(value).unwrap_or_else(|_| panic!("invalid session payload format"))
    }

    /// Return the validated format string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionPayloadFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SessionPayloadFormat")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for SessionPayloadFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for SessionPayloadFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SessionPayloadFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Product-owned payload schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionPayloadVersion(u16);

impl SessionPayloadVersion {
    /// Construct a payload schema version.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the numeric schema version.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl From<u16> for SessionPayloadVersion {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for SessionPayloadVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
    }
}

/// Redaction-safe product payload envelope.
///
/// The body is caller-owned encoded DTO bytes. `Debug` intentionally reports
/// only `body_len` so payload contents and subscriber data cannot leak through
/// diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionPayloadEnvelope {
    format: SessionPayloadFormat,
    version: SessionPayloadVersion,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl SessionPayloadEnvelope {
    /// Construct an envelope around caller-owned encoded body bytes.
    pub fn new(
        format: SessionPayloadFormat,
        version: SessionPayloadVersion,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            format,
            version,
            content_type: None,
            body: body.into(),
        }
    }

    /// Attach a validated content type marker to the envelope.
    pub fn with_content_type(
        mut self,
        content_type: impl Into<String>,
    ) -> Result<Self, SessionPayloadCodecError> {
        let content_type = content_type.into();
        validate_content_type(&content_type)?;
        self.content_type = Some(content_type);
        Ok(self)
    }

    /// Product payload format.
    pub fn format(&self) -> &SessionPayloadFormat {
        &self.format
    }

    /// Product payload schema version.
    pub fn version(&self) -> SessionPayloadVersion {
        self.version
    }

    /// Optional body content type marker.
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// Encoded product-owned body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    fn from_wire(wire: SessionPayloadEnvelopeWire) -> Result<Self, SessionPayloadCodecError> {
        let format = SessionPayloadFormat::new(wire.format)?;
        if let Some(content_type) = wire.content_type.as_deref() {
            validate_content_type(content_type)?;
        }
        Ok(Self {
            format,
            version: SessionPayloadVersion::new(wire.version),
            content_type: wire.content_type,
            body: wire.body,
        })
    }
}

impl fmt::Debug for SessionPayloadEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionPayloadEnvelope")
            .field("format", &self.format)
            .field("version", &self.version)
            .field("content_type", &self.content_type)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl Serialize for SessionPayloadEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("SessionPayloadEnvelope", 4)?;
        state.serialize_field("format", self.format.as_str())?;
        state.serialize_field("version", &self.version.get())?;
        state.serialize_field("content_type", &self.content_type)?;
        state.serialize_field("body", &self.body)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SessionPayloadEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SessionPayloadEnvelopeWire::deserialize(deserializer)?;
        Self::from_wire(wire).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionPayloadEnvelopeWire {
    format: String,
    version: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

/// Stable, redaction-safe error type for session payload envelope and codec operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SessionPayloadCodecError {
    /// The format identifier is empty, too long, or contains unsupported bytes.
    #[error("invalid session payload format")]
    InvalidFormat,
    /// The content type marker is empty, too long, or contains unsupported bytes.
    #[error("invalid session payload content type")]
    InvalidContentType,
    /// The decoded envelope format does not match the caller's expected format.
    #[error("session payload format mismatch")]
    FormatMismatch,
    /// The decoded envelope version is not supported by the caller.
    #[error("unsupported session payload version: expected {expected}, actual {actual}")]
    UnsupportedVersion {
        /// Expected schema version.
        expected: u16,
        /// Actual schema version from the envelope.
        actual: u16,
    },
    /// The envelope bytes are not valid envelope JSON or have an invalid shape.
    #[error("malformed session payload envelope")]
    MalformedEnvelope,
    /// The envelope declares a body content type the selected codec cannot decode.
    #[error("unsupported session payload content type")]
    UnsupportedContentType,
    /// The product-owned body bytes could not be decoded by the selected codec.
    #[error("malformed session payload body")]
    MalformedBody,
    /// The encoded payload exceeds the caller or backend byte limit.
    #[error("session payload too large: {actual} bytes exceeds maximum {max} bytes")]
    PayloadTooLarge {
        /// Maximum accepted byte length.
        max: usize,
        /// Actual encoded payload length.
        actual: usize,
    },
    /// The selected codec failed while encoding the product-owned DTO.
    #[error("session payload encode failed")]
    EncodeFailed,
    /// The selected codec failed while decoding the product-owned DTO.
    #[error("session payload decode failed")]
    DecodeFailed,
}

impl SessionPayloadCodecError {
    /// Stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidFormat => "invalid_format",
            Self::InvalidContentType => "invalid_content_type",
            Self::FormatMismatch => "format_mismatch",
            Self::UnsupportedVersion { .. } => "unsupported_version",
            Self::MalformedEnvelope => "malformed_envelope",
            Self::UnsupportedContentType => "unsupported_content_type",
            Self::MalformedBody => "malformed_body",
            Self::PayloadTooLarge { .. } => "payload_too_large",
            Self::EncodeFailed => "encode_failed",
            Self::DecodeFailed => "decode_failed",
        }
    }
}

/// Encode a product-owned envelope into caller-facing plaintext payload bytes.
pub fn encode_session_payload_envelope(
    envelope: &SessionPayloadEnvelope,
    max_bytes: Option<usize>,
) -> Result<EncryptedSessionPayload, SessionPayloadCodecError> {
    let bytes = serde_json::to_vec(envelope).map_err(|_| SessionPayloadCodecError::EncodeFailed)?;
    validate_len(bytes.len(), max_bytes)?;
    Ok(EncryptedSessionPayload::new(bytes))
}

/// Decode caller-facing plaintext payload bytes into a product-owned envelope.
pub fn decode_session_payload_envelope(
    payload: &EncryptedSessionPayload,
    max_bytes: Option<usize>,
) -> Result<SessionPayloadEnvelope, SessionPayloadCodecError> {
    validate_len(payload.len(), max_bytes)?;
    let wire: SessionPayloadEnvelopeWire = serde_json::from_slice(payload.as_bytes())
        .map_err(|_| SessionPayloadCodecError::MalformedEnvelope)?;
    SessionPayloadEnvelope::from_wire(wire).map_err(|err| match err {
        SessionPayloadCodecError::InvalidFormat | SessionPayloadCodecError::InvalidContentType => {
            err
        }
        _ => SessionPayloadCodecError::MalformedEnvelope,
    })
}

/// Encode a serializable product DTO as deterministic JSON inside an SDK envelope.
///
/// `serde_json` emits struct fields in declaration order and map entries in
/// the order provided by the map type. Products that require stable byte
/// equality across runs should use deterministic map types such as `BTreeMap`
/// in their DTOs.
pub fn encode_json_payload<T>(
    format: &SessionPayloadFormat,
    version: SessionPayloadVersion,
    value: &T,
    max_bytes: Option<usize>,
) -> Result<EncryptedSessionPayload, SessionPayloadCodecError>
where
    T: Serialize,
{
    let body = serde_json::to_vec(value).map_err(|_| SessionPayloadCodecError::EncodeFailed)?;
    let envelope = SessionPayloadEnvelope::new(format.clone(), version, body)
        .with_content_type(SESSION_PAYLOAD_JSON_CONTENT_TYPE)?;
    encode_session_payload_envelope(&envelope, max_bytes)
}

/// Decode a JSON product DTO from an SDK session payload envelope.
pub fn decode_json_payload<T>(
    payload: &EncryptedSessionPayload,
    expected_format: &SessionPayloadFormat,
    expected_version: SessionPayloadVersion,
    max_bytes: Option<usize>,
) -> Result<T, SessionPayloadCodecError>
where
    T: DeserializeOwned,
{
    let envelope = decode_session_payload_envelope(payload, max_bytes)?;
    if envelope.format() != expected_format {
        return Err(SessionPayloadCodecError::FormatMismatch);
    }
    if envelope.version() != expected_version {
        return Err(SessionPayloadCodecError::UnsupportedVersion {
            expected: expected_version.get(),
            actual: envelope.version().get(),
        });
    }
    if let Some(content_type) = envelope.content_type() {
        if content_type != SESSION_PAYLOAD_JSON_CONTENT_TYPE {
            return Err(SessionPayloadCodecError::UnsupportedContentType);
        }
    }

    serde_json::from_slice(envelope.body()).map_err(|_| SessionPayloadCodecError::MalformedBody)
}

/// Validate a session payload against a specific byte limit.
pub fn validate_session_payload_size(
    payload: &EncryptedSessionPayload,
    max_bytes: usize,
) -> Result<(), SessionPayloadCodecError> {
    validate_len(payload.len(), Some(max_bytes))
}

/// Validate a session payload against a backend's declared value-size limit.
pub fn validate_session_payload_size_for_backend(
    payload: &EncryptedSessionPayload,
    capabilities: &BackendCapabilities,
) -> Result<(), SessionPayloadCodecError> {
    validate_session_payload_size(payload, capabilities.max_value_bytes)
}

fn validate_len(actual: usize, max_bytes: Option<usize>) -> Result<(), SessionPayloadCodecError> {
    if let Some(max) = max_bytes {
        if actual > max {
            return Err(SessionPayloadCodecError::PayloadTooLarge { max, actual });
        }
    }
    Ok(())
}

fn validate_content_type(content_type: &str) -> Result<(), SessionPayloadCodecError> {
    if content_type.is_empty()
        || content_type.len() > MAX_CONTENT_TYPE_LEN
        || !content_type.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(SessionPayloadCodecError::InvalidContentType);
    }

    Ok(())
}
