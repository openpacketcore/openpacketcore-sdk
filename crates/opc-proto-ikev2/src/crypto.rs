//! Caller-owned IKEv2 protected-payload crypto boundary.
//!
//! @spec IETF RFC7296 3.14
//! @req REQ-IETF-RFC7296-3.14-CRYPTO-BOUNDARY-001

use std::{error::Error, fmt};

use bytes::Bytes;
use opc_protocol::{DecodeContext, DecodeError};

use crate::{header::Header, message::Message, payload::PayloadType, HEADER_LEN};

/// Kind of IKEv2 payload whose body is cryptographically protected.
///
/// @spec IETF RFC7296 3.14; IETF RFC7383 2.5
/// @req REQ-IETF-RFC7296-3.14-CRYPTO-BOUNDARY-002
/// @conformance boundary-only
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectedPayloadKind {
    /// Encrypted and Authenticated Payload (`SK`).
    Encrypted,
    /// Encrypted and Authenticated Fragment Payload (`SKF`).
    EncryptedFragment,
}

/// Metadata passed to a caller-provided IKEv2 crypto provider.
///
/// The SDK codec never chooses algorithms, keys, key lifetimes, peer policy, or
/// padding policy. It passes this metadata plus the protected payload body to a
/// downstream provider that owns SA state and cryptographic verification.
///
/// @spec IETF RFC7296 3.14
/// @req REQ-IETF-RFC7296-3.14-CRYPTO-BOUNDARY-003
/// @conformance boundary-only
#[derive(Clone, Copy)]
pub struct ProtectedPayloadContext<'a> {
    /// Decoded outer IKEv2 message header.
    pub header: &'a Header,
    /// Protected-payload kind that selected this boundary.
    pub kind: ProtectedPayloadKind,
    /// The generic protected-payload header's Next Payload value, which is the
    /// first inner payload type after successful decryption and padding checks.
    pub first_inner_payload: PayloadType,
    /// Byte offset of the protected generic payload from the payload region.
    ///
    /// Providers use this with [`crate::HEADER_LEN`] and
    /// [`crate::GENERIC_PAYLOAD_HEADER_LEN`] to reconstruct RFC 5282
    /// authenticated associated data exactly.
    pub payload_offset: usize,
    /// Complete outer IKEv2 message bytes, for providers whose integrity check
    /// covers header or associated-data fields.
    pub message_bytes: &'a [u8],
}

impl fmt::Debug for ProtectedPayloadContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedPayloadContext")
            .field("header", self.header)
            .field("kind", &self.kind)
            .field("first_inner_payload", &self.first_inner_payload)
            .field("payload_offset", &self.payload_offset)
            .field("message_bytes_len", &self.message_bytes.len())
            .finish()
    }
}

/// Trait implemented by downstream IKEv2 crypto/SPI state owners.
///
/// Implementations must authenticate and decrypt the protected payload body,
/// validate and remove padding according to their selected transform suite, and
/// return the cleartext inner payload-chain bytes. This crate intentionally
/// provides no concrete implementation: null crypto, algorithm negotiation, key
/// derivation, EAP-AKA, Child SA installation, and 3GPP profile decisions remain
/// downstream product responsibilities.
///
/// @spec IETF RFC7296 3.14
/// @req REQ-IETF-RFC7296-3.14-CRYPTO-BOUNDARY-004
/// @conformance boundary-only
pub trait CryptoProvider {
    /// Provider-specific error type; keep it redaction-safe for logs.
    type Error;

    /// Authenticate and decrypt a protected IKEv2 payload body.
    fn open_payload(
        &self,
        context: ProtectedPayloadContext<'_>,
        protected_body: &[u8],
    ) -> Result<Bytes, Self::Error>;
}

/// Opened IKEv2 protected-payload evidence plus caller-owned cleartext bytes.
///
/// `Debug` intentionally redacts the cleartext and reports only its length.
///
/// @spec IETF RFC7296 3.14
/// @req REQ-IETF-RFC7296-3.14-CRYPTO-BOUNDARY-005
/// @conformance boundary-only
#[derive(Clone, PartialEq, Eq)]
pub struct OpenedProtectedPayload {
    /// Protected-payload kind that was opened.
    pub kind: ProtectedPayloadKind,
    /// Byte offset of the protected generic payload from the payload region.
    pub offset: usize,
    /// Length of the encrypted/authenticated body supplied to the provider.
    pub protected_body_len: usize,
    /// First inner payload type reported by the protected generic header.
    pub first_inner_payload: PayloadType,
    /// Cleartext inner payload-chain bytes returned by the provider.
    pub cleartext: Bytes,
}

impl fmt::Debug for OpenedProtectedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedProtectedPayload")
            .field("kind", &self.kind)
            .field("offset", &self.offset)
            .field("protected_body_len", &self.protected_body_len)
            .field("first_inner_payload", &self.first_inner_payload)
            .field("cleartext_len", &self.cleartext.len())
            .finish()
    }
}

/// Redaction-safe provider failure evidence for one protected payload.
///
/// The provider error string is included because the provider owns the
/// redaction contract for its error type.
///
/// @spec IETF RFC7296 3.14
/// @req REQ-IETF-RFC7296-3.14-CRYPTO-BOUNDARY-006
/// @conformance boundary-only
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPayloadOpenFailure {
    /// Protected-payload kind whose provider open failed.
    pub kind: ProtectedPayloadKind,
    /// Byte offset of the protected generic payload from the payload region.
    pub offset: usize,
    /// Length of the encrypted/authenticated body supplied to the provider.
    pub protected_body_len: usize,
    /// First inner payload type reported by the protected generic header.
    pub first_inner_payload: PayloadType,
    /// Redaction-safe provider error text.
    pub provider_error: String,
}

/// Error returned while locating or opening IKEv2 protected payloads.
///
/// @spec IETF RFC7296 3.14
/// @req REQ-IETF-RFC7296-3.14-CRYPTO-BOUNDARY-007
/// @conformance boundary-only
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectedPayloadOpenError {
    /// Caller did not supply the exact outer IKE message length.
    MessageBytesLength {
        /// Expected complete IKE message length.
        expected: usize,
        /// Supplied byte slice length.
        actual: usize,
    },
    /// Caller-supplied bytes do not match the decoded payload region.
    MessagePayloadBytesMismatch,
    /// The generic payload chain could not be walked under the supplied decode context.
    PayloadDecode(DecodeError),
    /// The caller-owned provider rejected one protected payload.
    ProviderRejected(ProtectedPayloadOpenFailure),
}

impl ProtectedPayloadOpenError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MessageBytesLength { .. } => {
                "ike_protected_payload_message_bytes_length_mismatch"
            }
            Self::MessagePayloadBytesMismatch => "ike_protected_payload_message_payload_mismatch",
            Self::PayloadDecode(_) => "ike_protected_payload_decode_error",
            Self::ProviderRejected(_) => "ike_protected_payload_provider_rejected",
        }
    }
}

impl fmt::Display for ProtectedPayloadOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageBytesLength { expected, actual } => {
                write!(
                    f,
                    "IKE protected payload message bytes length mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::MessagePayloadBytesMismatch => {
                f.write_str("IKE protected payload message bytes do not match decoded payloads")
            }
            Self::PayloadDecode(error) => {
                write!(f, "IKE protected payload decode failed: {error}")
            }
            Self::ProviderRejected(failure) => {
                write!(
                    f,
                    "IKE protected payload provider rejected {:?} at offset {}: {}",
                    failure.kind, failure.offset, failure.provider_error
                )
            }
        }
    }
}

impl Error for ProtectedPayloadOpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PayloadDecode(error) => Some(error),
            _ => None,
        }
    }
}

/// Locate and open all protected payload boundaries in a decoded IKEv2 message.
///
/// The caller supplies the exact outer IKE message bytes so the provider can
/// authenticate the same associated data that arrived on the wire. This helper
/// verifies that the supplied bytes are the declared message length and match
/// the decoded payload region before delegating to the provider.
///
/// Transform negotiation, key lookup, padding policy, EAP-AKA, IKE SA state,
/// and product routing remain outside this crate.
///
/// # Errors
///
/// Returns [`ProtectedPayloadOpenError`] when the supplied message bytes do not
/// match the decoded message, when payload-chain iteration fails, or when the
/// caller-owned provider rejects a protected payload.
pub fn open_protected_payloads<P>(
    message: &Message<'_>,
    message_bytes: &[u8],
    ctx: DecodeContext,
    provider: &P,
) -> Result<Vec<OpenedProtectedPayload>, ProtectedPayloadOpenError>
where
    P: CryptoProvider,
    P::Error: fmt::Display,
{
    validate_message_bytes(message, message_bytes)?;

    let mut opened = Vec::new();
    for payload in message.payloads_with_context(ctx) {
        let payload = payload.map_err(ProtectedPayloadOpenError::PayloadDecode)?;
        let Some(kind) = payload.protected_kind() else {
            continue;
        };
        let context = ProtectedPayloadContext {
            header: &message.header,
            kind,
            first_inner_payload: payload.next_payload,
            payload_offset: payload.offset,
            message_bytes,
        };
        let cleartext = provider
            .open_payload(context, payload.body)
            .map_err(|error| {
                ProtectedPayloadOpenError::ProviderRejected(ProtectedPayloadOpenFailure {
                    kind,
                    offset: payload.offset,
                    protected_body_len: payload.body.len(),
                    first_inner_payload: payload.next_payload,
                    provider_error: error.to_string(),
                })
            })?;
        opened.push(OpenedProtectedPayload {
            kind,
            offset: payload.offset,
            protected_body_len: payload.body.len(),
            first_inner_payload: payload.next_payload,
            cleartext,
        });
    }

    Ok(opened)
}

fn validate_message_bytes(
    message: &Message<'_>,
    message_bytes: &[u8],
) -> Result<(), ProtectedPayloadOpenError> {
    let payload_len = message.payloads.bytes().len();
    let declared = HEADER_LEN.checked_add(payload_len).ok_or(
        ProtectedPayloadOpenError::MessageBytesLength {
            expected: usize::MAX,
            actual: payload_len,
        },
    )?;
    let header_len = usize::try_from(message.header.length).map_err(|_| {
        ProtectedPayloadOpenError::MessageBytesLength {
            expected: declared,
            actual: usize::MAX,
        }
    })?;
    if header_len != declared {
        return Err(ProtectedPayloadOpenError::MessageBytesLength {
            expected: declared,
            actual: header_len,
        });
    }
    if message_bytes.len() != declared {
        return Err(ProtectedPayloadOpenError::MessageBytesLength {
            expected: declared,
            actual: message_bytes.len(),
        });
    }

    match message_bytes.get(HEADER_LEN..) {
        Some(payload_bytes) if payload_bytes == message.payloads.bytes() => Ok(()),
        _ => Err(ProtectedPayloadOpenError::MessagePayloadBytesMismatch),
    }
}
