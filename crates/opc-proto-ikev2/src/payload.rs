//! IKEv2 generic payload-chain parsing.
//!
//! @spec IETF RFC7296 3.2
//! @req REQ-IETF-RFC7296-3.2-001

use opc_protocol::{DecodeContext, DecodeError, DecodeErrorCode, SpecRef};

use crate::{crypto::ProtectedPayloadKind, validation::Ikev2ValidationProfile};

/// IKEv2 generic payload header length in octets.
pub const GENERIC_PAYLOAD_HEADER_LEN: usize = 4;

fn spec_ref() -> SpecRef {
    SpecRef::new("ietf", "RFC7296", "3.2")
}

/// IKEv2 payload type values used by the generic payload chain.
///
/// Unknown values are preserved as raw payloads so callers can forward or store
/// messages without dropping extensions that this experimental scaffold does not
/// interpret.
///
/// @spec IETF RFC7296 3.2; IANA IKEv2 Payload Types
/// @req REQ-IETF-RFC7296-3.2-PAYLOAD-TYPE-001
/// @conformance experimental-scaffold
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadType {
    /// No Next Payload (0).
    NoNext,
    /// Security Association (`SA`, 33).
    SecurityAssociation,
    /// Key Exchange (`KE`, 34).
    KeyExchange,
    /// Identification - Initiator (`IDi`, 35).
    IdentificationInitiator,
    /// Identification - Responder (`IDr`, 36).
    IdentificationResponder,
    /// Certificate (`CERT`, 37).
    Certificate,
    /// Certificate Request (`CERTREQ`, 38).
    CertificateRequest,
    /// Authentication (`AUTH`, 39).
    Authentication,
    /// Nonce (`Ni`/`Nr`, 40).
    Nonce,
    /// Notify (`N`, 41).
    Notify,
    /// Delete (`D`, 42).
    Delete,
    /// Vendor ID (`V`, 43).
    VendorId,
    /// Traffic Selector - Initiator (`TSi`, 44).
    TrafficSelectorInitiator,
    /// Traffic Selector - Responder (`TSr`, 45).
    TrafficSelectorResponder,
    /// Encrypted and Authenticated Payload (`SK`, 46).
    Encrypted,
    /// Configuration (`CP`, 47).
    Configuration,
    /// Extensible Authentication Protocol (`EAP`, 48).
    ExtensibleAuthentication,
    /// Encrypted and Authenticated Fragment Payload (`SKF`, 53).
    EncryptedFragment,
    /// Unsupported or future payload type.
    Unknown(u8),
}

impl PayloadType {
    /// Convert a raw payload type octet to a typed view.
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::NoNext,
            33 => Self::SecurityAssociation,
            34 => Self::KeyExchange,
            35 => Self::IdentificationInitiator,
            36 => Self::IdentificationResponder,
            37 => Self::Certificate,
            38 => Self::CertificateRequest,
            39 => Self::Authentication,
            40 => Self::Nonce,
            41 => Self::Notify,
            42 => Self::Delete,
            43 => Self::VendorId,
            44 => Self::TrafficSelectorInitiator,
            45 => Self::TrafficSelectorResponder,
            46 => Self::Encrypted,
            47 => Self::Configuration,
            48 => Self::ExtensibleAuthentication,
            53 => Self::EncryptedFragment,
            other => Self::Unknown(other),
        }
    }

    /// Return the raw payload type octet.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::NoNext => 0,
            Self::SecurityAssociation => 33,
            Self::KeyExchange => 34,
            Self::IdentificationInitiator => 35,
            Self::IdentificationResponder => 36,
            Self::Certificate => 37,
            Self::CertificateRequest => 38,
            Self::Authentication => 39,
            Self::Nonce => 40,
            Self::Notify => 41,
            Self::Delete => 42,
            Self::VendorId => 43,
            Self::TrafficSelectorInitiator => 44,
            Self::TrafficSelectorResponder => 45,
            Self::Encrypted => 46,
            Self::Configuration => 47,
            Self::ExtensibleAuthentication => 48,
            Self::EncryptedFragment => 53,
            Self::Unknown(value) => value,
        }
    }

    /// Return protected-payload metadata when this payload requires crypto.
    pub const fn protected_kind(self) -> Option<ProtectedPayloadKind> {
        match self {
            Self::Encrypted => Some(ProtectedPayloadKind::Encrypted),
            Self::EncryptedFragment => Some(ProtectedPayloadKind::EncryptedFragment),
            _ => None,
        }
    }

    /// Return `true` when this is [`PayloadType::NoNext`].
    pub const fn is_no_next(self) -> bool {
        matches!(self, Self::NoNext)
    }
}

impl From<u8> for PayloadType {
    fn from(value: u8) -> Self {
        Self::from_u8(value)
    }
}

impl From<PayloadType> for u8 {
    fn from(value: PayloadType) -> Self {
        value.as_u8()
    }
}

/// Borrowed raw view of one IKEv2 generic payload.
///
/// The `payload_type` value is supplied by the previous chain link (or by the
/// outer IKE header for the first payload); `next_payload` is read from this
/// payload's generic header. For protected payloads, `next_payload` names the
/// first inner payload after downstream crypto opens the body, not another
/// cleartext outer payload.
///
/// @spec IETF RFC7296 3.2
/// @req REQ-IETF-RFC7296-3.2-RAW-PAYLOAD-001
/// @conformance experimental-scaffold
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawPayload<'a> {
    /// Payload type selected by the previous chain link.
    pub payload_type: PayloadType,
    /// Next Payload octet from this payload's generic header.
    pub next_payload: PayloadType,
    /// Critical bit from the generic payload header.
    pub critical: bool,
    /// Reserved low seven bits from the critical/reserved octet.
    pub reserved: u8,
    /// Payload length in octets, including the generic header.
    pub length: u16,
    /// Payload body after the generic header.
    pub body: &'a [u8],
    /// Byte offset of this payload from the start of the payload region.
    pub offset: usize,
}

impl RawPayload<'_> {
    /// Return protected-payload kind when the body is encrypted/authenticated.
    pub const fn protected_kind(&self) -> Option<ProtectedPayloadKind> {
        self.payload_type.protected_kind()
    }

    /// Return `true` when this payload body is protected and must not be parsed
    /// as cleartext by the codec scaffold.
    pub const fn is_protected(&self) -> bool {
        self.protected_kind().is_some()
    }
}

/// Borrowed raw payload-chain region.
///
/// @spec IETF RFC7296 3.2
/// @req REQ-IETF-RFC7296-3.2-CHAIN-001
/// @conformance experimental-scaffold
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadChain<'a> {
    first_payload: PayloadType,
    bytes: &'a [u8],
}

impl<'a> PayloadChain<'a> {
    /// Create a borrowed payload-chain view.
    pub const fn new(first_payload: PayloadType, bytes: &'a [u8]) -> Self {
        Self {
            first_payload,
            bytes,
        }
    }

    /// Return the first payload type supplied by the IKE fixed header.
    pub const fn first_payload(&self) -> PayloadType {
        self.first_payload
    }

    /// Return the raw payload-chain bytes.
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Return `true` when this message carries no payload bytes.
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Iterate over payloads using [`DecodeContext::default`].
    pub fn iter(&self) -> RawPayloadIterator<'a> {
        self.iter_with_context(DecodeContext::default())
    }

    /// Iterate over payloads using explicit parser limits and validation level.
    pub fn iter_with_context(&self, ctx: DecodeContext) -> RawPayloadIterator<'a> {
        RawPayloadIterator::new(self.first_payload, self.bytes, ctx)
    }

    /// Iterate over payloads with explicit parser limits and IKEv2 validation
    /// profile.
    pub fn iter_with_profile(
        &self,
        ctx: DecodeContext,
        profile: Ikev2ValidationProfile,
    ) -> RawPayloadIterator<'a> {
        RawPayloadIterator::new_with_profile(self.first_payload, self.bytes, ctx, profile)
    }

    /// Validate the payload chain under the supplied context.
    pub fn validate(&self, ctx: DecodeContext) -> Result<(), DecodeError> {
        validate_payload_chain(self.first_payload, self.bytes, ctx)
    }

    /// Validate the payload chain with an explicit IKEv2 validation profile.
    pub fn validate_with_profile(
        &self,
        ctx: DecodeContext,
        profile: Ikev2ValidationProfile,
    ) -> Result<(), DecodeError> {
        validate_payload_chain_with_profile(self.first_payload, self.bytes, ctx, profile)
    }
}

/// Lazy zero-copy iterator over an IKEv2 generic payload chain.
///
/// @spec IETF RFC7296 3.2
/// @req REQ-IETF-RFC7296-3.2-ITERATOR-001
/// @conformance experimental-scaffold
pub struct RawPayloadIterator<'a> {
    current_payload: PayloadType,
    remaining: &'a [u8],
    ctx: DecodeContext,
    profile: Ikev2ValidationProfile,
    offset: usize,
    seen: usize,
}

impl<'a> RawPayloadIterator<'a> {
    /// Create a new iterator over raw payload bytes.
    pub const fn new(first_payload: PayloadType, bytes: &'a [u8], ctx: DecodeContext) -> Self {
        Self::new_with_profile(
            first_payload,
            bytes,
            ctx,
            Ikev2ValidationProfile::NetworkReceive,
        )
    }

    /// Create a new iterator with an explicit IKEv2 validation profile.
    pub const fn new_with_profile(
        first_payload: PayloadType,
        bytes: &'a [u8],
        ctx: DecodeContext,
        profile: Ikev2ValidationProfile,
    ) -> Self {
        Self {
            current_payload: first_payload,
            remaining: bytes,
            ctx,
            profile,
            offset: 0,
            seen: 0,
        }
    }

    fn fail(&mut self, code: DecodeErrorCode, offset: usize, spec: SpecRef) -> DecodeError {
        self.current_payload = PayloadType::NoNext;
        self.remaining = &[];
        DecodeError::new(code, offset).with_spec_ref(spec)
    }
}

impl<'a> Iterator for RawPayloadIterator<'a> {
    type Item = Result<RawPayload<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        let spec = spec_ref();
        if self.current_payload.is_no_next() {
            if self.remaining.is_empty() {
                return None;
            }
            let offset = self.offset;
            return Some(Err(self.fail(
                DecodeErrorCode::Structural {
                    reason: "payload bytes remain after No Next Payload",
                },
                offset,
                spec,
            )));
        }

        if self.seen >= self.ctx.max_ies {
            let offset = self.offset;
            return Some(Err(self.fail(
                DecodeErrorCode::IeCountExceeded,
                offset,
                spec,
            )));
        }

        if self.remaining.len() < GENERIC_PAYLOAD_HEADER_LEN {
            let offset = self.offset;
            return Some(Err(self.fail(DecodeErrorCode::Truncated, offset, spec)));
        }

        let payload_type = self.current_payload;
        let next_payload = PayloadType::from_u8(self.remaining[0]);
        let critical_reserved = self.remaining[1];
        let critical = (critical_reserved & 0x80) != 0;
        let reserved = critical_reserved & 0x7f;
        let length = u16::from_be_bytes([self.remaining[2], self.remaining[3]]);
        let payload_len = length as usize;

        if self.profile.requires_sender_canonical_fields() && reserved != 0 {
            let offset = self.offset + 1;
            return Some(Err(self.fail(
                DecodeErrorCode::Structural {
                    reason: "IKEv2 generic payload reserved bits must be zero on send",
                },
                offset,
                spec,
            )));
        }

        if self.profile.requires_sender_canonical_fields()
            && critical
            && !matches!(payload_type, PayloadType::Unknown(_))
        {
            let offset = self.offset + 1;
            return Some(Err(self.fail(
                DecodeErrorCode::Structural {
                    reason: "known IKEv2 payload Critical bit must be zero on send",
                },
                offset,
                spec,
            )));
        }

        if matches!(payload_type, PayloadType::Unknown(_)) && critical {
            let offset = self.offset;
            return Some(Err(self.fail(
                DecodeErrorCode::UnknownCriticalIe,
                offset,
                spec,
            )));
        }

        if payload_len < GENERIC_PAYLOAD_HEADER_LEN {
            let offset = self.offset + 2;
            return Some(Err(self.fail(
                DecodeErrorCode::InvalidLength {
                    reason: "payload length shorter than generic header",
                },
                offset,
                spec,
            )));
        }
        if payload_len > self.remaining.len() {
            let offset = self.offset + self.remaining.len();
            return Some(Err(self.fail(DecodeErrorCode::Truncated, offset, spec)));
        }

        let body = &self.remaining[GENERIC_PAYLOAD_HEADER_LEN..payload_len];
        let tail = &self.remaining[payload_len..];
        let offset = self.offset;
        self.offset = match self.offset.checked_add(payload_len) {
            Some(value) => value,
            None => {
                return Some(Err(self.fail(
                    DecodeErrorCode::LengthOverflow,
                    offset,
                    spec,
                )));
            }
        };
        self.remaining = tail;
        self.seen += 1;
        self.current_payload = if payload_type.protected_kind().is_some() {
            PayloadType::NoNext
        } else {
            next_payload
        };

        Some(Ok(RawPayload {
            payload_type,
            next_payload,
            critical,
            reserved,
            length,
            body,
            offset,
        }))
    }
}

/// Validate an IKEv2 generic payload chain without allocating.
///
/// @spec IETF RFC7296 3.2
/// @req REQ-IETF-RFC7296-3.2-VALIDATE-001
/// @conformance experimental-scaffold
pub fn validate_payload_chain(
    first_payload: PayloadType,
    bytes: &[u8],
    ctx: DecodeContext,
) -> Result<(), DecodeError> {
    validate_payload_chain_with_profile(
        first_payload,
        bytes,
        ctx,
        Ikev2ValidationProfile::NetworkReceive,
    )
}

/// Validate an IKEv2 generic payload chain with an explicit profile.
///
/// Network receive validation ignores the generic-header reserved bits as RFC
/// 7296 requires, while still rejecting malformed lengths, excessive payload
/// counts, impossible chaining, and unknown critical payloads. Sender-canonical
/// validation additionally requires those reserved bits to be zero.
///
/// @spec IETF RFC7296 2.5, 3.2
/// @req REQ-IETF-RFC7296-3.2-VALIDATE-002
/// @conformance experimental-scaffold
pub fn validate_payload_chain_with_profile(
    first_payload: PayloadType,
    bytes: &[u8],
    ctx: DecodeContext,
    profile: Ikev2ValidationProfile,
) -> Result<(), DecodeError> {
    if first_payload.is_no_next() && bytes.is_empty() {
        return Ok(());
    }
    if first_payload.is_no_next() && !bytes.is_empty() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "payload bytes present with No Next Payload in IKE header",
            },
            0,
        )
        .with_spec_ref(spec_ref()));
    }

    let mut iterator = RawPayloadIterator::new_with_profile(first_payload, bytes, ctx, profile);
    for item in &mut iterator {
        let _payload = item?;
    }
    Ok(())
}
