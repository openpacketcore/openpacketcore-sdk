//! Caller-owned IKEv2 protected-payload crypto boundary.
//!
//! @spec IETF RFC7296 3.14
//! @req REQ-IETF-RFC7296-3.14-CRYPTO-BOUNDARY-001

use bytes::Bytes;

use crate::{header::Header, payload::PayloadType};

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
#[derive(Debug, Clone, Copy)]
pub struct ProtectedPayloadContext<'a> {
    /// Decoded outer IKEv2 message header.
    pub header: &'a Header,
    /// Protected-payload kind that selected this boundary.
    pub kind: ProtectedPayloadKind,
    /// The generic protected-payload header's Next Payload value, which is the
    /// first inner payload type after successful decryption and padding checks.
    pub first_inner_payload: PayloadType,
    /// Complete outer IKEv2 message bytes, for providers whose integrity check
    /// covers header or associated-data fields.
    pub message_bytes: &'a [u8],
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
