#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! Experimental Diameter protocol crate for OpenPacketCore.
//!
//! This crate starts the SDK-owned Diameter mechanism surface described by ADR
//! 0018. It provides RFC 6733 header and raw AVP framing, dictionary metadata,
//! feature-gated base peer procedure helpers, and skeleton dictionaries for
//! initial 3GPP application work. It deliberately does **not** implement product
//! policy such as realm routing, AAA/HSS behavior, charging decisions, watchdog
//! thresholds, or peer transport operations.
//! [`end_to_end`] provides a bounded origin-scoped RFC 6733 End-to-End
//! Identifier authority with an injectable fallible clock, an exact
//! four-minute duplicate fence, an affine authority attestation bound to a
//! redacted Origin-Host scope, and an affine request identity that must match
//! its originating scope before consumption. Checked SWm envelope constructors
//! read the typed request Origin-Host directly. Diagnostics do not expose scope
//! fingerprints or identifier values.
//! With the `peer` feature, [`peer::PeerSession`] also provides an explicit,
//! generation-bound RFC 6733 direct or in-band TLS/TCP and DTLS/SCTP readiness
//! and header-admission boundary. A typed requirement retains both mechanism and
//! sequence. Direct protection admits no Diameter before exact-generation
//! attestation and still withholds application readiness until CER/CEA succeeds.
//! In-band protection permits one correlated CER/CEA, then blocks every Diameter
//! message until the selected mechanism is attested. Each transport candidate
//! has exactly one CER role; simultaneous-open election remains transport-owned.
//! The boundary produces a responder's exact matching, typed CEA once as
//! immutable canonical bytes. Generation-bound lifecycle mutations re-evaluate
//! exact-header command admission, and a CEA E-bit must match its Result-Code
//! family before capability evidence is consumed. This is state-machine evidence
//! only: protected framing,
//! certificate validation, credential rotation, and crypto-provider selection
//! remain transport-owned.
//! `error_answer` adds the bounded RFC 6733 request envelope and negative-
//! answer boundary without exposing sensitive AVP contents or retaining an
//! unbounded request suffix.
//! `parser_error` adds sealed, request-bound missing-AVP and grouped-set
//! provenance for the typed CER, DWR, DPR, and SWm DER/STR/ASR/RAR/AAR parsers. Legacy parser
//! signatures continue to return [`DecodeError`]; additive
//! `*_with_provenance` entry points retain the command/application identity and
//! exact SDK-owned vendor-aware AVP schema required by
//! `DiameterRequestFailure::from_parser_error` to safely bind actual missing-
//! field failures to 5005. CER `Vendor-Specific-Application-Id` mutual-
//! exclusion failures retain exact received Auth/Acct children for typed 5009.
//!
//! The crate is experimental and not yet an ADR 0015 conformance claim; see
//! `CONFORMANCE.md` before treating any fixture or dictionary entry as release
//! evidence.
//!
//! @spec IETF RFC6733
//! @req REQ-IETF-RFC6733-SCAFFOLD-001
//! @conformance scaffold — see CONFORMANCE.md

use std::collections::HashSet;

#[cfg(any(
    feature = "app-gx",
    feature = "app-rf",
    feature = "app-s6a",
    feature = "app-s6b",
    feature = "app-swm",
    feature = "app-swx"
))]
pub mod apps;
#[cfg(feature = "base")]
pub mod avp;
#[cfg(feature = "base")]
pub mod base;
pub mod dictionary;
pub mod end_to_end;
#[cfg(feature = "base")]
pub mod error_answer;
#[cfg(feature = "base")]
pub mod parser_error;
#[cfg(feature = "peer")]
pub mod peer;

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, DuplicateIePolicy,
    Encode, EncodeContext, EncodeError, EncodeErrorCode, OwnedDecode, SpecRef, ToOwnedPdu,
    ValidationLevel,
};

pub use dictionary::{
    ApplicationDefinition, AvpCardinality, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey,
    CommandAvpRule, CommandDefinition, CommandKind, CommandLookupError, Dictionary, DictionarySet,
    FlagRequirement,
};

/// Diameter protocol version defined by RFC 6733.
pub const DIAMETER_VERSION: u8 = 1;
/// Fixed Diameter message header size in octets.
pub const DIAMETER_HEADER_LEN: usize = 20;
/// Fixed AVP header size without a Vendor-Id field.
pub const AVP_HEADER_LEN: usize = 8;
/// Fixed AVP header size with a Vendor-Id field.
pub const AVP_VENDOR_HEADER_LEN: usize = 12;
/// Maximum value representable by a Diameter 24-bit length or command-code field.
pub const MAX_U24: u32 = 0x00FF_FFFF;

/// Diameter application identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApplicationId(u32);

impl ApplicationId {
    /// Create an application identifier.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the numeric identifier.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Diameter command code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandCode(u32);

impl CommandCode {
    /// Create a command code.
    ///
    /// Encoders reject values greater than [`MAX_U24`] because the wire field
    /// is 24 bits wide.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the numeric command code.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Return true when the code fits in the Diameter 24-bit wire field.
    pub const fn fits_wire(self) -> bool {
        self.0 <= MAX_U24
    }
}

/// Diameter AVP code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AvpCode(u32);

impl AvpCode {
    /// Create an AVP code.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the numeric AVP code.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Diameter vendor identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VendorId(u32);

impl VendorId {
    /// Create a vendor identifier.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the numeric vendor identifier.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Diameter command flags from RFC 6733 section 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommandFlags(u8);

impl CommandFlags {
    /// Request flag (`R`, bit 7).
    pub const REQUEST: u8 = 0x80;
    /// Proxiable flag (`P`, bit 6).
    pub const PROXIABLE: u8 = 0x40;
    /// Error flag (`E`, bit 5).
    pub const ERROR: u8 = 0x20;
    /// Potentially re-transmitted flag (`T`, bit 4).
    pub const POTENTIALLY_RETRANSMITTED: u8 = 0x10;
    /// Reserved flag bits that must be zero in strict mode.
    pub const RESERVED_MASK: u8 = 0x0F;

    /// Create flags from raw wire bits.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Create request flags with the requested proxiable setting.
    pub const fn request(proxiable: bool) -> Self {
        let mut bits = Self::REQUEST;
        if proxiable {
            bits |= Self::PROXIABLE;
        }
        Self(bits)
    }

    /// Create answer flags with the requested proxiable and error settings.
    pub const fn answer(proxiable: bool, error: bool) -> Self {
        let mut bits = 0;
        if proxiable {
            bits |= Self::PROXIABLE;
        }
        if error {
            bits |= Self::ERROR;
        }
        Self(bits)
    }

    /// Return raw wire bits.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Return whether the request bit is set.
    pub const fn is_request(self) -> bool {
        self.0 & Self::REQUEST != 0
    }

    /// Return whether the proxiable bit is set.
    pub const fn is_proxiable(self) -> bool {
        self.0 & Self::PROXIABLE != 0
    }

    /// Return whether the error bit is set.
    pub const fn is_error(self) -> bool {
        self.0 & Self::ERROR != 0
    }

    /// Return whether the potentially re-transmitted bit is set.
    pub const fn is_potentially_retransmitted(self) -> bool {
        self.0 & Self::POTENTIALLY_RETRANSMITTED != 0
    }

    /// Return the reserved flag bits.
    pub const fn reserved_bits(self) -> u8 {
        self.0 & Self::RESERVED_MASK
    }

    /// Return the command dictionary role implied by the R bit.
    pub const fn command_kind(self) -> CommandKind {
        if self.is_request() {
            CommandKind::Request
        } else {
            CommandKind::Answer
        }
    }
}

/// Diameter AVP flags from RFC 6733 section 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AvpFlags(u8);

impl AvpFlags {
    /// Vendor-specific flag (`V`, bit 7).
    pub const VENDOR: u8 = 0x80;
    /// Mandatory flag (`M`, bit 6).
    pub const MANDATORY: u8 = 0x40;
    /// End-to-end encryption flag (`P`, bit 5), reserved by RFC 6733.
    pub const PROTECTED: u8 = 0x20;
    /// Reserved flag bits that must be zero in strict mode.
    pub const RESERVED_MASK: u8 = 0x1F;

    /// Create AVP flags from raw wire bits.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Create AVP flags from boolean components.
    pub const fn new(vendor: bool, mandatory: bool, protected: bool) -> Self {
        let mut bits = 0;
        if vendor {
            bits |= Self::VENDOR;
        }
        if mandatory {
            bits |= Self::MANDATORY;
        }
        if protected {
            bits |= Self::PROTECTED;
        }
        Self(bits)
    }

    /// Return raw wire bits.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Return whether the Vendor-Specific bit is set.
    pub const fn is_vendor_specific(self) -> bool {
        self.0 & Self::VENDOR != 0
    }

    /// Return whether the Mandatory bit is set.
    pub const fn is_mandatory(self) -> bool {
        self.0 & Self::MANDATORY != 0
    }

    /// Return whether the Protected bit is set.
    pub const fn is_protected(self) -> bool {
        self.0 & Self::PROTECTED != 0
    }

    /// Return the reserved flag bits.
    pub const fn reserved_bits(self) -> u8 {
        self.0 & Self::RESERVED_MASK
    }
}

/// Diameter message header.
///
/// @spec IETF RFC6733 3
/// @req REQ-IETF-RFC6733-3-001
/// @conformance scaffold
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Diameter version; RFC 6733 defines version 1.
    pub version: u8,
    /// Message length including the fixed header and AVPs.
    pub length: u32,
    /// Command flags.
    pub flags: CommandFlags,
    /// Diameter command code.
    pub command_code: CommandCode,
    /// Diameter application identifier.
    pub application_id: ApplicationId,
    /// Hop-by-Hop Identifier.
    pub hop_by_hop_identifier: u32,
    /// End-to-End Identifier.
    pub end_to_end_identifier: u32,
}

impl Header {
    /// Create a Diameter header with the fixed header length.
    pub const fn new(
        flags: CommandFlags,
        command_code: CommandCode,
        application_id: ApplicationId,
        hop_by_hop_identifier: u32,
        end_to_end_identifier: u32,
    ) -> Self {
        Self {
            version: DIAMETER_VERSION,
            length: DIAMETER_HEADER_LEN as u32,
            flags,
            command_code,
            application_id,
            hop_by_hop_identifier,
            end_to_end_identifier,
        }
    }

    /// Return a copy of this header with a different length field.
    pub const fn with_length(mut self, length: u32) -> Self {
        self.length = length;
        self
    }

    /// Return the fixed Diameter header wire length.
    pub const fn wire_header_len(&self) -> usize {
        DIAMETER_HEADER_LEN
    }
}

impl<'a> BorrowDecode<'a> for Header {
    /// Decode a Diameter header from the front of the input.
    ///
    /// @spec IETF RFC6733 3
    /// @req REQ-IETF-RFC6733-3-002
    /// @conformance scaffold
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        let spec_ref = SpecRef::new("ietf", "RFC6733", "3");
        if input.len() < DIAMETER_HEADER_LEN {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec_ref));
        }

        let version = input[0];
        if version != DIAMETER_VERSION {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidEnumValue {
                    field: "version",
                    value: version as u64,
                },
                0,
            )
            .with_spec_ref(spec_ref));
        }

        let length = read_u24(&input[1..4]);
        if length < DIAMETER_HEADER_LEN as u32 {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "diameter message length is shorter than the fixed header",
                },
                1,
            )
            .with_spec_ref(spec_ref));
        }
        if length as usize > ctx.max_message_len {
            return Err(
                DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 1).with_spec_ref(spec_ref)
            );
        }

        let flags = CommandFlags::from_bits(input[4]);
        if strict_validation(ctx.validation_level) && flags.reserved_bits() != 0 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "diameter command reserved flag bits must be zero",
                },
                4,
            )
            .with_spec_ref(spec_ref));
        }

        let command_code = CommandCode::new(read_u24(&input[5..8]));
        let application_id = ApplicationId::new(u32::from_be_bytes([
            input[8], input[9], input[10], input[11],
        ]));
        let hop_by_hop_identifier =
            u32::from_be_bytes([input[12], input[13], input[14], input[15]]);
        let end_to_end_identifier =
            u32::from_be_bytes([input[16], input[17], input[18], input[19]]);

        Ok((
            &input[DIAMETER_HEADER_LEN..],
            Self {
                version,
                length,
                flags,
                command_code,
                application_id,
                hop_by_hop_identifier,
                end_to_end_identifier,
            },
        ))
    }
}

impl Encode for Header {
    /// Encode a Diameter header.
    ///
    /// @spec IETF RFC6733 3
    /// @req REQ-IETF-RFC6733-3-003
    /// @conformance scaffold
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        self.validate_for_encode(ctx)?;
        dst.put_u8(self.version);
        put_u24(dst, self.length);
        dst.put_u8(self.flags.bits());
        put_u24(dst, self.command_code.get());
        dst.put_u32(self.application_id.get());
        dst.put_u32(self.hop_by_hop_identifier);
        dst.put_u32(self.end_to_end_identifier);
        Ok(())
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        self.validate_for_encode(ctx)?;
        Ok(DIAMETER_HEADER_LEN)
    }
}

impl Header {
    fn validate_for_encode(&self, ctx: EncodeContext) -> Result<(), EncodeError> {
        let spec_ref = SpecRef::new("ietf", "RFC6733", "3");
        ctx.check_capacity(DIAMETER_HEADER_LEN)?;
        if self.version != DIAMETER_VERSION {
            return Err(EncodeError::new(EncodeErrorCode::Structural {
                reason: "diameter version must be 1",
            })
            .with_spec_ref(spec_ref));
        }
        if self.length < DIAMETER_HEADER_LEN as u32 || self.length > MAX_U24 {
            return Err(EncodeError::new(EncodeErrorCode::Structural {
                reason: "diameter message length must fit the 24-bit field and include the header",
            })
            .with_spec_ref(spec_ref));
        }
        if !self.command_code.fits_wire() {
            return Err(EncodeError::new(EncodeErrorCode::Structural {
                reason: "diameter command code must fit the 24-bit field",
            })
            .with_spec_ref(spec_ref));
        }
        if !ctx.raw_preserving && self.flags.reserved_bits() != 0 {
            return Err(EncodeError::new(EncodeErrorCode::Structural {
                reason: "diameter command reserved flag bits must be zero",
            })
            .with_spec_ref(spec_ref));
        }
        Ok(())
    }
}

/// Borrowed Diameter message preserving raw AVP bytes.
///
/// @spec IETF RFC6733 3
/// @req REQ-IETF-RFC6733-3-004
/// @conformance scaffold
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// Parsed Diameter header.
    pub header: Header,
    /// Raw AVP region, including AVP padding exactly as received.
    pub raw_avps: &'a [u8],
    /// Bytes after the message boundary declared by the header length.
    pub tail: &'a [u8],
}

impl<'a> Message<'a> {
    /// Decode a message against exactly one trusted application command grammar.
    ///
    /// Unlike [`BorrowDecode::decode`], this entry point permits only AVPs that
    /// the resolved command metadata explicitly marks repeatable to bypass
    /// [`DuplicateIePolicy::Reject`]. Command resolution includes application
    /// identifier, command code, and request/answer role, and fails closed when
    /// the supplied dictionary set is missing or ambiguous.
    pub fn decode_with_dictionary(
        input: &'a [u8],
        ctx: DecodeContext,
        dictionaries: DictionarySet<'_>,
    ) -> DecodeResult<'a, Self> {
        // Decode framing and all non-duplicate structural constraints first.
        // Command-aware validation below applies the caller's actual duplicate
        // policy after the header has selected one trusted grammar.
        let framing_ctx = DecodeContext {
            duplicate_ie_policy: DuplicateIePolicy::First,
            ..ctx
        };
        let (tail, message) = Self::decode(input, framing_ctx)?;
        message.resolve_command(dictionaries)?;
        if ctx.validation_level != ValidationLevel::HeaderOnly {
            message.validate_command_avps_with_dictionary(ctx, dictionaries)?;
        }
        Ok((tail, message))
    }

    /// Return an iterator over raw top-level AVPs.
    pub fn avps(&self, ctx: DecodeContext) -> RawAvpIterator<'a> {
        RawAvpIterator::new(self.raw_avps, ctx)
    }

    /// Validate the top-level AVP region with offsets relative to the message start.
    pub fn validate_avps(&self, ctx: DecodeContext) -> Result<(), DecodeError> {
        validate_top_level_avps(self.raw_avps, ctx)
    }

    /// Validate AVPs and dictionary-defined grouped AVP values recursively.
    ///
    /// The returned error offsets are relative to the Diameter message start.
    pub fn validate_avps_with_dictionary(
        &self,
        ctx: DecodeContext,
        dictionaries: DictionarySet<'_>,
    ) -> Result<(), DecodeError> {
        validate_avp_region_at(
            self.raw_avps,
            ctx,
            DIAMETER_HEADER_LEN,
            0,
            Some(dictionaries),
            None,
        )
    }

    /// Validate this message using its uniquely resolved command cardinality.
    ///
    /// Error offsets are relative to the Diameter message start. Only
    /// top-level AVPs explicitly declared repeatable by the resolved command
    /// may repeat. Within a known Grouped AVP, only children explicitly
    /// declared repeatable by that grouped definition may repeat.
    pub fn validate_command_avps_with_dictionary(
        &self,
        ctx: DecodeContext,
        dictionaries: DictionarySet<'_>,
    ) -> Result<(), DecodeError> {
        let command = self.resolve_command(dictionaries)?;
        validate_avp_region_at(
            self.raw_avps,
            ctx,
            DIAMETER_HEADER_LEN,
            0,
            Some(dictionaries),
            Some(command.avp_rules()),
        )
    }

    fn resolve_command<'dictionary>(
        &self,
        dictionaries: DictionarySet<'dictionary>,
    ) -> Result<&'dictionary CommandDefinition, DecodeError> {
        dictionaries
            .resolve_command(
                self.header.application_id,
                self.header.command_code,
                self.header.flags.command_kind(),
            )
            .map_err(|error| {
                let reason = match error {
                    CommandLookupError::Missing => {
                        "diameter command grammar is missing for application, code, and role"
                    }
                    CommandLookupError::Ambiguous => {
                        "diameter command grammar is ambiguous for application, code, and role"
                    }
                };
                DecodeError::new(DecodeErrorCode::Structural { reason }, 5)
                    .with_spec_ref(SpecRef::new("ietf", "RFC6733", "3"))
            })
    }

    fn encoded_len(&self) -> Result<u32, EncodeError> {
        let len = DIAMETER_HEADER_LEN
            .checked_add(self.raw_avps.len())
            .ok_or_else(EncodeError::length_overflow)?;
        u32::try_from(len).map_err(|_| EncodeError::length_overflow())
    }
}

impl<'a> BorrowDecode<'a> for Message<'a> {
    /// Decode a Diameter message, honoring the header length boundary.
    ///
    /// @spec IETF RFC6733 3
    /// @req REQ-IETF-RFC6733-3-005
    /// @conformance scaffold
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        let spec_ref = SpecRef::new("ietf", "RFC6733", "3");
        let (_, header) = Header::decode(input, ctx)?;
        let msg_end = header.length as usize;
        if input.len() < msg_end {
            return Err(
                DecodeError::new(DecodeErrorCode::Incomplete, input.len()).with_spec_ref(spec_ref)
            );
        }
        let raw_avps = &input[DIAMETER_HEADER_LEN..msg_end];
        if ctx.validation_level != ValidationLevel::HeaderOnly {
            validate_top_level_avps(raw_avps, ctx)?;
        }
        let tail = &input[msg_end..];
        Ok((
            tail,
            Self {
                header,
                raw_avps,
                tail,
            },
        ))
    }
}

impl Encode for Message<'_> {
    /// Encode a Diameter message, recomputing the header length from raw AVPs.
    ///
    /// @spec IETF RFC6733 3
    /// @req REQ-IETF-RFC6733-3-006
    /// @conformance scaffold
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let length = self.encoded_len()?;
        let required = usize::try_from(length).map_err(|_| EncodeError::length_overflow())?;
        ctx.check_capacity(required)?;
        let header = self.header.clone().with_length(length);
        header.encode(dst, ctx)?;
        dst.put_slice(self.raw_avps);
        Ok(())
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        let length = self.encoded_len()?;
        let required = usize::try_from(length).map_err(|_| EncodeError::length_overflow())?;
        ctx.check_capacity(required)?;
        Ok(required)
    }
}

impl<'a> ToOwnedPdu for Message<'a> {
    type Owned = OwnedMessage;

    fn to_owned_pdu(&self) -> Self::Owned {
        Self::Owned {
            header: self.header.clone(),
            raw_avps: Bytes::copy_from_slice(self.raw_avps),
        }
    }
}

/// Owned Diameter message preserving raw AVP bytes.
///
/// # Logging safety
///
/// This low-level type intentionally derives `Debug`, which includes
/// `raw_avps` byte-for-byte and may therefore disclose Session-Id, proxy state,
/// subscriber identity, or authentication material. Never log or format an
/// `OwnedMessage` from untrusted or production traffic. Prefer redacted typed
/// projections such as `DiameterErrorAnswerPlan` for diagnostics.
///
/// @spec IETF RFC6733 3
/// @req REQ-IETF-RFC6733-3-007
/// @conformance scaffold
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedMessage {
    /// Parsed Diameter header.
    pub header: Header,
    /// Raw AVP region, including AVP padding exactly as received.
    pub raw_avps: Bytes,
}

impl OwnedMessage {
    fn as_borrowed(&self) -> Message<'_> {
        Message {
            header: self.header.clone(),
            raw_avps: &self.raw_avps,
            tail: &[],
        }
    }

    /// Decode an owned message against exactly one trusted command grammar.
    pub fn decode_owned_with_dictionary(
        input: Bytes,
        ctx: DecodeContext,
        dictionaries: DictionarySet<'_>,
    ) -> Result<Self, DecodeError> {
        let (_, borrowed) = Message::decode_with_dictionary(&input, ctx, dictionaries)?;
        let msg_end = borrowed.header.length as usize;
        Ok(Self {
            header: borrowed.header,
            raw_avps: input.slice(DIAMETER_HEADER_LEN..msg_end),
        })
    }
}

impl OwnedDecode for OwnedMessage {
    /// Decode an owned Diameter message.
    ///
    /// @spec IETF RFC6733 3
    /// @req REQ-IETF-RFC6733-3-008
    /// @conformance scaffold
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (_, borrowed) = Message::decode(&input, ctx)?;
        let msg_end = borrowed.header.length as usize;
        Ok(Self {
            header: borrowed.header,
            raw_avps: input.slice(DIAMETER_HEADER_LEN..msg_end),
        })
    }
}

impl Encode for OwnedMessage {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        self.as_borrowed().encode(dst, ctx)
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        self.as_borrowed().wire_len(ctx)
    }
}

/// Diameter AVP header.
///
/// @spec IETF RFC6733 4
/// @req REQ-IETF-RFC6733-4-001
/// @conformance scaffold
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvpHeader {
    /// AVP code.
    pub code: AvpCode,
    /// AVP flags.
    pub flags: AvpFlags,
    /// AVP length excluding padding and including this header.
    pub length: u32,
    /// Vendor identifier when the V bit is set.
    pub vendor_id: Option<VendorId>,
}

impl AvpHeader {
    /// Create a non-vendor AVP header with a placeholder header-only length.
    pub const fn ietf(code: AvpCode, mandatory: bool) -> Self {
        Self {
            code,
            flags: AvpFlags::new(false, mandatory, false),
            length: AVP_HEADER_LEN as u32,
            vendor_id: None,
        }
    }

    /// Create a vendor-specific AVP header with a placeholder header-only length.
    pub const fn vendor(code: AvpCode, vendor_id: VendorId, mandatory: bool) -> Self {
        Self {
            code,
            flags: AvpFlags::new(true, mandatory, false),
            length: AVP_VENDOR_HEADER_LEN as u32,
            vendor_id: Some(vendor_id),
        }
    }

    /// Return the AVP key described by this header.
    pub const fn key(&self) -> AvpKey {
        match self.vendor_id {
            Some(vendor_id) => AvpKey::vendor(self.code, vendor_id),
            None => AvpKey::ietf(self.code),
        }
    }

    /// Return this AVP header with a different AVP length.
    pub const fn with_length(mut self, length: u32) -> Self {
        self.length = length;
        self
    }

    /// Return this AVP header with raw flags.
    pub const fn with_flags(mut self, flags: AvpFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Return the AVP header length implied by the V bit.
    pub const fn header_len(&self) -> usize {
        if self.flags.is_vendor_specific() {
            AVP_VENDOR_HEADER_LEN
        } else {
            AVP_HEADER_LEN
        }
    }

    fn validate_for_encode(&self, ctx: EncodeContext) -> Result<(), EncodeError> {
        let spec_ref = SpecRef::new("ietf", "RFC6733", "4");
        if self.length > MAX_U24 || self.length < self.header_len() as u32 {
            return Err(EncodeError::new(EncodeErrorCode::Structural {
                reason: "diameter AVP length must fit the 24-bit field and include the AVP header",
            })
            .with_spec_ref(spec_ref));
        }
        if self.flags.is_vendor_specific() != self.vendor_id.is_some() {
            return Err(EncodeError::new(EncodeErrorCode::Structural {
                reason: "diameter AVP V bit and Vendor-Id presence differ",
            })
            .with_spec_ref(spec_ref));
        }
        if !ctx.raw_preserving && self.flags.reserved_bits() != 0 {
            return Err(EncodeError::new(EncodeErrorCode::Structural {
                reason: "diameter AVP reserved flag bits must be zero",
            })
            .with_spec_ref(spec_ref));
        }
        Ok(())
    }

    fn encode_header(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        self.validate_for_encode(ctx)?;
        dst.put_u32(self.code.get());
        dst.put_u8(self.flags.bits());
        put_u24(dst, self.length);
        if let Some(vendor_id) = self.vendor_id {
            dst.put_u32(vendor_id.get());
        }
        Ok(())
    }
}

/// Borrowed raw AVP preserving the value and padding bytes.
///
/// @spec IETF RFC6733 4
/// @req REQ-IETF-RFC6733-4-002
/// @conformance scaffold
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAvp<'a> {
    /// Parsed AVP header.
    pub header: AvpHeader,
    /// AVP value bytes.
    pub value: &'a [u8],
    /// Padding bytes after the AVP value.
    pub padding: &'a [u8],
}

#[cfg(feature = "base")]
pub(crate) fn append_canonical_avp(
    dst: &mut BytesMut,
    header: AvpHeader,
    value: &[u8],
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let avp = RawAvp {
        header,
        value,
        padding: &[],
    };
    let canonical_ctx = EncodeContext {
        raw_preserving: false,
        ..ctx
    };
    let required = dst
        .len()
        .checked_add(avp.wire_len(canonical_ctx)?)
        .ok_or_else(EncodeError::length_overflow)?;
    ctx.check_capacity(required)?;
    avp.encode(dst, canonical_ctx)
}

impl<'a> BorrowDecode<'a> for RawAvp<'a> {
    /// Decode one raw Diameter AVP from the front of the input.
    ///
    /// @spec IETF RFC6733 4
    /// @req REQ-IETF-RFC6733-4-003
    /// @conformance scaffold
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        decode_raw_avp(input, ctx)
    }
}

impl Encode for RawAvp<'_> {
    /// Encode one raw Diameter AVP, recomputing its AVP length field.
    ///
    /// @spec IETF RFC6733 4
    /// @req REQ-IETF-RFC6733-4-004
    /// @conformance scaffold
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let (length, padded_len) = self.encoded_lens()?;
        ctx.check_capacity(padded_len)?;
        let header = self.header.clone().with_length(length);
        header.encode_header(dst, ctx)?;
        dst.put_slice(self.value);
        let padding_len = padded_len
            .checked_sub(length as usize)
            .ok_or_else(EncodeError::length_overflow)?;
        if ctx.raw_preserving {
            if self.padding.len() != padding_len {
                return Err(EncodeError::new(EncodeErrorCode::Structural {
                    reason: "diameter AVP preserved padding length does not match canonical padding length",
                })
                .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4")));
            }
            dst.put_slice(self.padding);
        } else {
            dst.put_bytes(0, padding_len);
        }
        Ok(())
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        let (_, padded_len) = self.encoded_lens()?;
        ctx.check_capacity(padded_len)?;
        Ok(padded_len)
    }
}

impl<'a> RawAvp<'a> {
    /// Return an iterator over this AVP's value as a grouped AVP region.
    ///
    /// Iterator error offsets are relative to the grouped value slice.
    pub fn grouped_avps(&self, ctx: DecodeContext) -> RawAvpIterator<'a> {
        RawAvpIterator::new(self.value, ctx)
    }

    /// Validate this AVP's value as a grouped AVP region.
    ///
    /// The returned error offsets are relative to the grouped value slice.
    pub fn validate_grouped_value(&self, ctx: DecodeContext) -> Result<(), DecodeError> {
        validate_avp_region_at(self.value, ctx, 0, 1, None, None)
    }

    /// Validate this AVP's value and dictionary-defined nested grouped AVPs recursively.
    ///
    /// The returned error offsets are relative to the grouped value slice.
    pub fn validate_grouped_value_with_dictionary(
        &self,
        ctx: DecodeContext,
        dictionaries: DictionarySet<'_>,
    ) -> Result<(), DecodeError> {
        validate_avp_region_at(self.value, ctx, 0, 1, Some(dictionaries), None)
    }

    fn encoded_lens(&self) -> Result<(u32, usize), EncodeError> {
        let header_len = self.header.header_len();
        let unpadded = header_len
            .checked_add(self.value.len())
            .ok_or_else(EncodeError::length_overflow)?;
        if unpadded > MAX_U24 as usize {
            return Err(EncodeError::length_overflow());
        }
        let padded = align4(unpadded).ok_or_else(EncodeError::length_overflow)?;
        let length = u32::try_from(unpadded).map_err(|_| EncodeError::length_overflow())?;
        Ok((length, padded))
    }
}

/// Iterator over a borrowed raw AVP region.
pub struct RawAvpIterator<'a> {
    remaining: &'a [u8],
    ctx: DecodeContext,
    exhausted: bool,
}

impl<'a> RawAvpIterator<'a> {
    /// Create a raw AVP iterator.
    pub const fn new(input: &'a [u8], ctx: DecodeContext) -> Self {
        Self {
            remaining: input,
            ctx,
            exhausted: false,
        }
    }
}

impl<'a> Iterator for RawAvpIterator<'a> {
    type Item = Result<RawAvp<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted || self.remaining.is_empty() {
            return None;
        }
        match RawAvp::decode(self.remaining, self.ctx) {
            Ok((remaining, avp)) => {
                self.remaining = remaining;
                Some(Ok(avp))
            }
            Err(error) => {
                self.exhausted = true;
                Some(Err(error))
            }
        }
    }
}

/// Validate a Diameter AVP region as a sequence of raw AVPs.
///
/// Error offsets are relative to the start of `input`. This validates AVP
/// length fields, padding, per-region AVP counts, and duplicate AVP keys
/// according to the supplied [`DecodeContext`]. It does not recurse into
/// grouped AVP values without dictionary metadata; use
/// [`validate_avp_region_with_dictionary`] for dictionary-defined grouped AVPs.
pub fn validate_avp_region(input: &[u8], ctx: DecodeContext) -> Result<(), DecodeError> {
    validate_avp_region_at(input, ctx, 0, 0, None, None)
}

/// Validate a Diameter AVP region using dictionary metadata for grouped AVPs.
///
/// Error offsets are relative to the start of `input`. AVPs whose dictionary
/// definition has [`AvpDataType::Grouped`] are recursively validated as nested
/// AVP regions, bounded by [`DecodeContext::max_depth`].
pub fn validate_avp_region_with_dictionary(
    input: &[u8],
    ctx: DecodeContext,
    dictionaries: DictionarySet<'_>,
) -> Result<(), DecodeError> {
    validate_avp_region_at(input, ctx, 0, 0, Some(dictionaries), None)
}

fn decode_raw_avp<'a>(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, RawAvp<'a>> {
    let spec_ref = SpecRef::new("ietf", "RFC6733", "4");
    if input.len() < AVP_HEADER_LEN {
        return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec_ref));
    }

    let code = AvpCode::new(u32::from_be_bytes([input[0], input[1], input[2], input[3]]));
    let flags = AvpFlags::from_bits(input[4]);
    if strict_validation(ctx.validation_level) && flags.reserved_bits() != 0 {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "diameter AVP reserved flag bits must be zero",
            },
            4,
        )
        .with_spec_ref(spec_ref));
    }

    let length = read_u24(&input[5..8]);
    let header_len = if flags.is_vendor_specific() {
        AVP_VENDOR_HEADER_LEN
    } else {
        AVP_HEADER_LEN
    };
    if input.len() < header_len {
        return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec_ref));
    }
    if length < header_len as u32 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidLength {
                reason: "diameter AVP length is shorter than the AVP header",
            },
            5,
        )
        .with_spec_ref(spec_ref));
    }

    let length_usize = length as usize;
    let padded_len = align4(length_usize).ok_or_else(|| {
        DecodeError::new(DecodeErrorCode::LengthOverflow, 5).with_spec_ref(spec_ref.clone())
    })?;
    if input.len() < padded_len {
        return Err(
            DecodeError::new(DecodeErrorCode::Truncated, input.len()).with_spec_ref(spec_ref)
        );
    }

    let vendor_id = if flags.is_vendor_specific() {
        Some(VendorId::new(u32::from_be_bytes([
            input[8], input[9], input[10], input[11],
        ])))
    } else {
        None
    };
    let header = AvpHeader {
        code,
        flags,
        length,
        vendor_id,
    };
    let value = &input[header_len..length_usize];
    let padding = &input[length_usize..padded_len];
    if strict_validation(ctx.validation_level) && padding.iter().any(|byte| *byte != 0) {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "diameter AVP padding must be zero",
            },
            length_usize,
        )
        .with_spec_ref(spec_ref));
    }

    Ok((
        &input[padded_len..],
        RawAvp {
            header,
            value,
            padding,
        },
    ))
}

fn validate_top_level_avps(input: &[u8], ctx: DecodeContext) -> Result<(), DecodeError> {
    validate_avp_region_at(input, ctx, DIAMETER_HEADER_LEN, 0, None, None)
}

fn validate_avp_region_at(
    input: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
    dictionaries: Option<DictionarySet<'_>>,
    occurrence_rules: Option<&[CommandAvpRule]>,
) -> Result<(), DecodeError> {
    let spec_ref = SpecRef::new("ietf", "RFC6733", "4");
    // This catches public grouped-value entry points (which start at depth 1)
    // as well as any direct call with a depth already over the limit.
    if depth > ctx.max_depth {
        return Err(
            DecodeError::new(DecodeErrorCode::DepthExceeded, base_offset).with_spec_ref(spec_ref),
        );
    }

    let mut remaining = input;
    let mut relative_offset = 0usize;
    let mut avp_count = 0usize;
    let mut seen_keys: Option<HashSet<AvpKey>> = None;

    while !remaining.is_empty() {
        let offset = base_offset.checked_add(relative_offset).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, base_offset)
                .with_spec_ref(spec_ref.clone())
        })?;
        avp_count = avp_count.checked_add(1).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                .with_spec_ref(spec_ref.clone())
        })?;
        if avp_count > ctx.max_ies {
            return Err(
                DecodeError::new(DecodeErrorCode::IeCountExceeded, offset).with_spec_ref(spec_ref)
            );
        }

        let before = remaining.len();
        let (next, avp) = match RawAvp::decode(remaining, ctx) {
            Ok(decoded) => decoded,
            Err(error) => return Err(shift_decode_error(error, offset)),
        };

        let key = avp.header.key();
        if occurrence_rules
            .and_then(|rules| rules.iter().find(|rule| rule.key() == key))
            .is_some_and(|rule| rule.cardinality().is_forbidden())
        {
            return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, offset)
                .with_spec_ref(spec_ref));
        }

        if ctx.duplicate_ie_policy == DuplicateIePolicy::Reject {
            let repeated = !seen_keys.get_or_insert_with(HashSet::new).insert(key);
            let repeatable = occurrence_rules
                .and_then(|rules| rules.iter().find(|rule| rule.key() == key))
                .map(|rule| rule.cardinality().allows_multiple())
                .unwrap_or(false);
            if repeated && !repeatable {
                return Err(
                    DecodeError::new(DecodeErrorCode::DuplicateIe, offset).with_spec_ref(spec_ref)
                );
            }
        }

        if let Some(grouped_rules) = dictionary_grouped_avp_rules(&avp, dictionaries) {
            let child_depth = depth.saturating_add(1);
            // The entry-level guard catches depth violations from direct callers;
            // this early check gives an offset pointing to the grouping AVP rather
            // than to the first child inside it when recursing from a parent region.
            if child_depth > ctx.max_depth {
                return Err(DecodeError::new(DecodeErrorCode::DepthExceeded, offset)
                    .with_spec_ref(spec_ref));
            }
            let child_base = offset.checked_add(avp.header.header_len()).ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                    .with_spec_ref(spec_ref.clone())
            })?;
            validate_avp_region_at(
                avp.value,
                ctx,
                child_base,
                child_depth,
                dictionaries,
                Some(grouped_rules),
            )?;
        }

        let consumed = before.checked_sub(next.len()).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                .with_spec_ref(spec_ref.clone())
        })?;
        relative_offset = relative_offset.checked_add(consumed).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                .with_spec_ref(spec_ref.clone())
        })?;
        remaining = next;
    }

    Ok(())
}

fn dictionary_grouped_avp_rules<'dictionary>(
    avp: &RawAvp<'_>,
    dictionaries: Option<DictionarySet<'dictionary>>,
) -> Option<&'dictionary [CommandAvpRule]> {
    let dictionaries = dictionaries?;
    dictionaries
        .find_avp(avp.header.key())
        .filter(|definition| definition.data_type() == AvpDataType::Grouped)
        .map(AvpDefinition::grouped_avp_rules)
}

fn shift_decode_error(error: DecodeError, base_offset: usize) -> DecodeError {
    let offset = match base_offset.checked_add(error.offset()) {
        Some(offset) => offset,
        None => return DecodeError::new(DecodeErrorCode::LengthOverflow, base_offset),
    };
    let shifted = DecodeError::new(error.code().clone(), offset);
    match error.spec_ref().cloned() {
        Some(spec_ref) => shifted.with_spec_ref(spec_ref),
        None => shifted,
    }
}

fn strict_validation(level: ValidationLevel) -> bool {
    matches!(
        level,
        ValidationLevel::Strict | ValidationLevel::ProcedureAware
    )
}

fn read_u24(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32
}

fn put_u24(dst: &mut BytesMut, value: u32) {
    dst.put_u8(((value >> 16) & 0xFF) as u8);
    dst.put_u8(((value >> 8) & 0xFF) as u8);
    dst.put_u8((value & 0xFF) as u8);
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|padded| padded & !3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use quickcheck::{Arbitrary, Gen, TestResult};

    const CARDINALITY_TEST_APPLICATION: ApplicationId = ApplicationId::new(4_242);
    const CARDINALITY_TEST_COMMAND: CommandCode = CommandCode::new(4_243);
    const CARDINALITY_TEST_AVP: AvpCode = AvpCode::new(4_244);
    const CARDINALITY_TEST_VENDOR: VendorId = VendorId::new(10_415);
    static CARDINALITY_TEST_RULES: [CommandAvpRule; 1] = [CommandAvpRule::new(
        AvpKey::vendor(CARDINALITY_TEST_AVP, CARDINALITY_TEST_VENDOR),
        AvpCardinality::ZeroOrMore,
    )];
    static CARDINALITY_TEST_COMMANDS: [CommandDefinition; 1] = [CommandDefinition::new(
        CARDINALITY_TEST_COMMAND,
        "Cardinality-Test-Request",
        CommandKind::Request,
        CARDINALITY_TEST_APPLICATION,
        false,
        SpecRef::new("ietf", "RFC6733", "4"),
    )
    .with_avp_rules(&CARDINALITY_TEST_RULES)];
    static CARDINALITY_TEST_AVPS: [AvpDefinition; 1] = [AvpDefinition::new(
        AvpKey::vendor(CARDINALITY_TEST_AVP, CARDINALITY_TEST_VENDOR),
        "Cardinality-Test-AVP",
        AvpDataType::OctetString,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("ietf", "RFC6733", "4"),
    )];
    static CARDINALITY_TEST_DICTIONARY: Dictionary = Dictionary::new(
        "diameter-cardinality-property-test",
        &[],
        &CARDINALITY_TEST_COMMANDS,
        &CARDINALITY_TEST_AVPS,
    );
    static CARDINALITY_TEST_DICTIONARIES: DictionarySet<'static> =
        DictionarySet::new(&[&CARDINALITY_TEST_DICTIONARY]);

    #[derive(Clone, Debug)]
    struct ValidDiameterMessageBytes(Vec<u8>);

    impl ValidDiameterMessageBytes {
        fn as_slice(&self) -> &[u8] {
            self.0.as_slice()
        }
    }

    impl Arbitrary for ValidDiameterMessageBytes {
        fn arbitrary(g: &mut Gen) -> Self {
            let avp_count = (u8::arbitrary(g) % 4) as usize;
            let mut raw_avps = BytesMut::new();

            for avp_index in 0..avp_count {
                let vendor_specific = bool::arbitrary(g);
                let mut value = Vec::<u8>::arbitrary(g);
                value.truncate(256);

                let code = (u32::arbitrary(g) & 0xFFFF_FF00) | avp_index as u32;
                let vendor_id = if vendor_specific {
                    Some(u32::arbitrary(g))
                } else {
                    None
                };
                let mut flags = 0;
                if vendor_specific {
                    flags |= AvpFlags::VENDOR;
                }
                if bool::arbitrary(g) {
                    flags |= AvpFlags::MANDATORY;
                }
                if bool::arbitrary(g) {
                    flags |= AvpFlags::PROTECTED;
                }

                let header_len = if vendor_specific {
                    AVP_VENDOR_HEADER_LEN
                } else {
                    AVP_HEADER_LEN
                };
                let avp_len = (header_len + value.len()) as u32;
                raw_avps.put_u32(code);
                raw_avps.put_u8(flags);
                put_u24(&mut raw_avps, avp_len);
                if let Some(vendor_id) = vendor_id {
                    raw_avps.put_u32(vendor_id);
                }
                raw_avps.put_slice(&value);

                let padding_len = (4 - (avp_len as usize % 4)) % 4;
                raw_avps.put_bytes(0, padding_len);
            }

            let command_flags = u8::arbitrary(g)
                & (CommandFlags::REQUEST
                    | CommandFlags::PROXIABLE
                    | CommandFlags::ERROR
                    | CommandFlags::POTENTIALLY_RETRANSMITTED);
            let header = Header::new(
                CommandFlags::from_bits(command_flags),
                CommandCode::new(u32::arbitrary(g) & MAX_U24),
                ApplicationId::new(u32::arbitrary(g)),
                u32::arbitrary(g),
                u32::arbitrary(g),
            )
            .with_length((DIAMETER_HEADER_LEN + raw_avps.len()) as u32);

            let mut encoded = BytesMut::new();
            if let Err(error) = header.encode(&mut encoded, EncodeContext::default()) {
                panic!("generated Diameter header encode failed: {error}");
            }
            encoded.put_slice(&raw_avps);
            Self(encoded.to_vec())
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct RawAvpView {
        code: AvpCode,
        flags: AvpFlags,
        vendor_id: Option<VendorId>,
        value: Vec<u8>,
    }

    quickcheck::quickcheck! {
        fn prop_message_decode_roundtrip(bytes: ValidDiameterMessageBytes) -> TestResult {
            let decode_ctx = DecodeContext::default();
            let (_tail, message) = match Message::decode(bytes.as_slice(), decode_ctx) {
                Ok(decoded) => decoded,
                Err(_) => return TestResult::discard(),
            };

            let mut encoded = BytesMut::new();
            if let Err(error) = message.encode(&mut encoded, EncodeContext::default()) {
                panic!("Diameter message encode failed: {error}");
            }

            let (encoded_tail, roundtripped) = match Message::decode(&encoded, decode_ctx) {
                Ok(decoded) => decoded,
                Err(error) => panic!("roundtripped Diameter message decode failed: {error}"),
            };
            assert!(encoded_tail.is_empty());
            assert_eq!(roundtripped.header, message.header);
            assert_eq!(
                raw_avp_views(&roundtripped, decode_ctx),
                raw_avp_views(&message, decode_ctx)
            );

            TestResult::passed()
        }

        fn prop_command_repeatability_is_vendor_aware(other_vendor: u32) -> bool {
            let other_vendor = if other_vendor == CARDINALITY_TEST_VENDOR.get() {
                other_vendor.wrapping_add(1)
            } else {
                other_vendor
            };
            let ctx = DecodeContext {
                unknown_ie_policy: opc_protocol::UnknownIePolicy::Preserve,
                ..DecodeContext::conservative()
            };

            let allowed_avp = encode_empty_vendor_cardinality_avp(CARDINALITY_TEST_VENDOR);
            let mut allowed_region = BytesMut::new();
            allowed_region.put_slice(&allowed_avp);
            allowed_region.put_slice(&allowed_avp);
            let allowed = encode_cardinality_test_message(&allowed_region);

            let other_avp = encode_empty_vendor_cardinality_avp(VendorId::new(other_vendor));
            let mut other_region = BytesMut::new();
            other_region.put_slice(&other_avp);
            other_region.put_slice(&other_avp);
            let other = encode_cardinality_test_message(&other_region);

            let mut mixed_region = BytesMut::new();
            mixed_region.put_slice(&allowed_avp);
            mixed_region.put_slice(&other_avp);
            let mixed = encode_cardinality_test_message(&mixed_region);

            Message::decode_with_dictionary(&allowed, ctx, CARDINALITY_TEST_DICTIONARIES).is_ok()
                && Message::decode_with_dictionary(&mixed, ctx, CARDINALITY_TEST_DICTIONARIES)
                    .is_ok()
                && matches!(
                    Message::decode_with_dictionary(
                        &other,
                        ctx,
                        CARDINALITY_TEST_DICTIONARIES,
                    ),
                    Err(error) if matches!(error.code(), DecodeErrorCode::DuplicateIe)
                        && error.offset() == DIAMETER_HEADER_LEN + other_avp.len()
                )
        }
    }

    fn encode_empty_vendor_cardinality_avp(vendor_id: VendorId) -> BytesMut {
        let avp = RawAvp {
            header: AvpHeader::vendor(CARDINALITY_TEST_AVP, vendor_id, false),
            value: &[],
            padding: &[],
        };
        let mut encoded = BytesMut::new();
        if let Err(error) = avp.encode(&mut encoded, EncodeContext::default()) {
            panic!("cardinality test AVP encode failed: {error}");
        }
        encoded
    }

    fn encode_cardinality_test_message(raw_avps: &[u8]) -> BytesMut {
        let message = Message {
            header: Header::new(
                CommandFlags::request(false),
                CARDINALITY_TEST_COMMAND,
                CARDINALITY_TEST_APPLICATION,
                1,
                2,
            ),
            raw_avps,
            tail: &[],
        };
        let mut encoded = BytesMut::new();
        if let Err(error) = message.encode(&mut encoded, EncodeContext::default()) {
            panic!("cardinality test message encode failed: {error}");
        }
        encoded
    }

    fn raw_avp_views(message: &Message<'_>, ctx: DecodeContext) -> Vec<RawAvpView> {
        let mut views = Vec::new();
        for avp in message.avps(ctx) {
            match avp {
                Ok(avp) => views.push(RawAvpView {
                    code: avp.header.code,
                    flags: avp.header.flags,
                    vendor_id: avp.header.vendor_id,
                    value: avp.value.to_vec(),
                }),
                Err(error) => panic!("raw AVP iteration failed: {error}"),
            }
        }
        views
    }

    fn encode_message(raw_avps: &[u8], tail: &[u8]) -> BytesMut {
        let header = Header::new(
            CommandFlags::request(false),
            CommandCode::new(257),
            ApplicationId::new(0),
            0x0102_0304,
            0xA0B0_C0D0,
        )
        .with_length((DIAMETER_HEADER_LEN + raw_avps.len()) as u32);
        let mut encoded = BytesMut::new();
        if let Err(error) = header.encode(&mut encoded, EncodeContext::default()) {
            panic!("message header encode failed: {error}");
        }
        encoded.put_slice(raw_avps);
        encoded.put_slice(tail);
        encoded
    }

    fn empty_avp(code: u32) -> [u8; AVP_HEADER_LEN] {
        [
            ((code >> 24) & 0xFF) as u8,
            ((code >> 16) & 0xFF) as u8,
            ((code >> 8) & 0xFF) as u8,
            (code & 0xFF) as u8,
            0x40,
            0x00,
            0x00,
            AVP_HEADER_LEN as u8,
        ]
    }

    #[test]
    fn header_round_trip_preserves_wire_fields() {
        let header = Header::new(
            CommandFlags::request(true),
            CommandCode::new(257),
            ApplicationId::new(0),
            0x0102_0304,
            0xA0B0_C0D0,
        );
        let mut encoded = BytesMut::new();
        assert!(header
            .encode(&mut encoded, EncodeContext::default())
            .is_ok());
        match Header::decode(&encoded, DecodeContext::default()) {
            Ok((remaining, decoded)) => {
                assert!(remaining.is_empty());
                assert_eq!(decoded, header);
            }
            Err(error) => panic!("header decode failed: {error}"),
        }
    }

    #[test]
    fn raw_avp_accounts_for_padding() {
        let avp = RawAvp {
            header: AvpHeader::ietf(AvpCode::new(264), true),
            value: b"h",
            padding: b"\0\0\0",
        };
        let mut encoded = BytesMut::new();
        let ctx = EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        };
        assert!(avp.encode(&mut encoded, ctx).is_ok());
        match RawAvp::decode(&encoded, DecodeContext::default()) {
            Ok((remaining, decoded)) => {
                assert!(remaining.is_empty());
                assert_eq!(decoded.value, b"h");
                assert_eq!(decoded.padding, b"\0\0\0");
            }
            Err(error) => panic!("raw AVP decode failed: {error}"),
        }
    }

    #[test]
    fn rejects_truncated_header() {
        let result = Header::decode(&[DIAMETER_VERSION, 0, 0], DecodeContext::default());
        assert!(matches!(
            result,
            Err(error) if matches!(error.code(), DecodeErrorCode::Truncated)
        ));
    }

    #[test]
    fn rejects_invalid_version() {
        let mut encoded = encode_message(&[], &[]);
        encoded[0] = 2;
        let result = Header::decode(&encoded, DecodeContext::default());
        assert!(matches!(
            result,
            Err(error) if matches!(
                error.code(),
                DecodeErrorCode::InvalidEnumValue { field: "version", value: 2 }
            )
        ));
    }

    #[test]
    fn strict_mode_rejects_command_reserved_bits() {
        let mut encoded = encode_message(&[], &[]);
        encoded[4] = CommandFlags::REQUEST | 0x01;
        let result = Header::decode(&encoded, DecodeContext::conservative());
        assert!(matches!(
            result,
            Err(error) if matches!(
                error.code(),
                DecodeErrorCode::Structural {
                    reason: "diameter command reserved flag bits must be zero"
                }
            )
        ));
    }

    #[test]
    fn message_length_limit_is_enforced() {
        let mut ctx = DecodeContext {
            max_message_len: DIAMETER_HEADER_LEN - 1,
            ..DecodeContext::default()
        };
        ctx.validation_level = ValidationLevel::Structural;
        let encoded = encode_message(&[], &[]);
        let result = Header::decode(&encoded, ctx);
        assert!(matches!(
            result,
            Err(error) if matches!(error.code(), DecodeErrorCode::MessageLengthExceeded)
        ));
    }

    #[test]
    fn rejects_avp_length_shorter_than_header() {
        let avp = [0, 0, 1, 8, 0x40, 0, 0, 7];
        let result = RawAvp::decode(&avp, DecodeContext::default());
        assert!(matches!(
            result,
            Err(error) if matches!(
                error.code(),
                DecodeErrorCode::InvalidLength {
                    reason: "diameter AVP length is shorter than the AVP header"
                }
            )
        ));
    }

    #[test]
    fn strict_mode_rejects_non_zero_padding() {
        let avp = [0, 0, 1, 8, 0x40, 0, 0, 9, b'h', 1, 0, 0];
        let result = RawAvp::decode(&avp, DecodeContext::conservative());
        assert!(matches!(
            result,
            Err(error) if matches!(
                error.code(),
                DecodeErrorCode::Structural {
                    reason: "diameter AVP padding must be zero"
                }
            )
        ));
    }

    #[test]
    fn message_decode_enforces_ie_count_limit() {
        let mut avps = BytesMut::new();
        avps.put_slice(&empty_avp(264));
        avps.put_slice(&empty_avp(296));
        let encoded = encode_message(&avps, &[]);
        let ctx = DecodeContext {
            max_ies: 1,
            ..DecodeContext::default()
        };
        let result = Message::decode(&encoded, ctx);
        assert!(matches!(
            result,
            Err(error) if matches!(error.code(), DecodeErrorCode::IeCountExceeded)
                && error.offset() == DIAMETER_HEADER_LEN + AVP_HEADER_LEN
        ));
    }

    #[test]
    fn vendor_specific_avp_round_trip_preserves_vendor_id_and_padding() {
        let avp = RawAvp {
            header: AvpHeader::vendor(AvpCode::new(7000), VendorId::new(10415), true),
            value: b"abc",
            padding: b"\0",
        };
        let ctx = EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        };
        let mut encoded = BytesMut::new();
        assert!(avp.encode(&mut encoded, ctx).is_ok());
        match RawAvp::decode(&encoded, DecodeContext::default()) {
            Ok((remaining, decoded)) => {
                assert!(remaining.is_empty());
                assert_eq!(decoded.header.vendor_id, Some(VendorId::new(10415)));
                assert_eq!(decoded.value, b"abc");
                assert_eq!(decoded.padding, b"\0");
                let mut reencoded = BytesMut::new();
                assert!(decoded.encode(&mut reencoded, ctx).is_ok());
                assert_eq!(reencoded, encoded);
            }
            Err(error) => panic!("vendor AVP decode failed: {error}"),
        }
    }

    #[test]
    fn message_decode_preserves_tail_and_owned_slice_boundary() {
        let avp = empty_avp(264);
        let encoded = encode_message(&avp, &[0xAA, 0xBB]);
        match Message::decode(&encoded, DecodeContext::default()) {
            Ok((tail, decoded)) => {
                assert_eq!(tail, &[0xAA, 0xBB]);
                assert_eq!(decoded.tail, &[0xAA, 0xBB]);
                assert_eq!(decoded.raw_avps, &avp);
            }
            Err(error) => panic!("message decode failed: {error}"),
        }
        match OwnedMessage::decode_owned(Bytes::copy_from_slice(&encoded), DecodeContext::default())
        {
            Ok(decoded) => assert_eq!(decoded.raw_avps, Bytes::copy_from_slice(&avp)),
            Err(error) => panic!("owned message decode failed: {error}"),
        }
    }

    #[test]
    fn raw_avp_iterator_stops_after_first_error() {
        let mut input = BytesMut::new();
        input.put_slice(&empty_avp(264));
        input.put_slice(&[0x00, 0x01]);
        let mut iter = RawAvpIterator::new(&input, DecodeContext::default());
        assert!(matches!(iter.next(), Some(Ok(_))));
        assert!(matches!(
            iter.next(),
            Some(Err(error)) if matches!(error.code(), DecodeErrorCode::Truncated)
        ));
        assert!(iter.next().is_none());
    }

    #[test]
    fn message_avp_errors_use_absolute_offsets() {
        let mut avps = BytesMut::new();
        avps.put_slice(&empty_avp(264));
        avps.put_slice(&[0, 0, 1, 8, 0x40, 0, 0, 7]);
        let encoded = encode_message(&avps, &[]);
        let result = Message::decode(&encoded, DecodeContext::default());
        assert!(matches!(
            result,
            Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
                && error.offset() == DIAMETER_HEADER_LEN + AVP_HEADER_LEN + 5
        ));
    }
}
