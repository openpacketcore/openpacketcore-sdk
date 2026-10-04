use std::fmt;

use crate::{eap5g, EapAkaError, EapAkaPacket};

/// Stable EAP admission errors containing no received values or packet bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EapPacketError {
    /// The four-octet common header is incomplete.
    #[error("eap_truncated_header")]
    TruncatedHeader,
    /// The Code is not Request, Response, Success or Failure.
    #[error("eap_unsupported_code")]
    UnsupportedCode,
    /// Length cannot contain the common header or a Request/Response Type.
    #[error("eap_invalid_length")]
    InvalidLength,
    /// Length declares more octets than were received.
    #[error("eap_length_mismatch")]
    LengthMismatch,
    /// A Success or Failure declares Data; its Length must be exactly four.
    #[error("eap_invalid_terminal_length")]
    InvalidTerminalLength,
}

/// An EAP Success (Code 3), with no Type or Data (RFC 3748 section 4.2).
///
/// The identifier must equal that of the last Response being answered.
/// Construction and parsing do not establish that authentication succeeded;
/// the caller owns method verification and exchange state. Debug omits the
/// identifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EapSuccess {
    identifier: u8,
}

impl EapSuccess {
    /// Construct a Success using the identifier of the Response being answered.
    #[must_use]
    pub const fn new(identifier: u8) -> Self {
        Self { identifier }
    }

    /// Return the EAP Identifier for caller-owned exchange correlation.
    #[must_use]
    pub const fn identifier(self) -> u8 {
        self.identifier
    }

    /// Encode exactly `[3, identifier, 0, 4]`, without allocating.
    #[must_use]
    pub const fn encode(self) -> [u8; 4] {
        [3, self.identifier, 0, 4]
    }

    /// Check equality with the last Response's identifier (RFC 3748 section 4.2).
    ///
    /// The caller supplies the identifier from its current exchange. Equality
    /// alone does not authenticate the packet or establish method completion.
    #[must_use]
    pub const fn matches_response_identifier(self, last_response_identifier: u8) -> bool {
        self.identifier == last_response_identifier
    }
}

impl fmt::Debug for EapSuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EapSuccess").finish_non_exhaustive()
    }
}

/// An EAP Failure (Code 4), with no Type or Data (RFC 3748 section 4.2).
///
/// The identifier must equal that of the last Response being answered.
/// Construction and parsing do not make an authentication decision; the caller
/// owns method verification and exchange state. Debug omits the identifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EapFailure {
    identifier: u8,
}

impl EapFailure {
    /// Construct a Failure using the identifier of the Response being answered.
    #[must_use]
    pub const fn new(identifier: u8) -> Self {
        Self { identifier }
    }

    /// Return the EAP Identifier for caller-owned exchange correlation.
    #[must_use]
    pub const fn identifier(self) -> u8 {
        self.identifier
    }

    /// Encode exactly `[4, identifier, 0, 4]`, without allocating.
    #[must_use]
    pub const fn encode(self) -> [u8; 4] {
        [4, self.identifier, 0, 4]
    }

    /// Check equality with the last Response's identifier (RFC 3748 section 4.2).
    ///
    /// The caller supplies the identifier from its current exchange. Equality
    /// alone does not authenticate the packet or establish method completion.
    #[must_use]
    pub const fn matches_response_identifier(self, last_response_identifier: u8) -> bool {
        self.identifier == last_response_identifier
    }
}

impl fmt::Debug for EapFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EapFailure").finish_non_exhaustive()
    }
}

/// A Request or Response admitted by common framing, before method validation.
///
/// This private borrow contains exactly the declared EAP Length, excluding
/// lower-layer padding. Method parsing is explicit and preserves each existing
/// parser's validation and errors. No raw bytes are exposed, and Debug contains
/// neither the identifier nor packet values.
#[derive(Clone, Copy)]
pub struct EapMethodPacket<'a> {
    packet: &'a [u8],
}

impl<'a> EapMethodPacket<'a> {
    /// Return the EAP Identifier for caller-owned exchange correlation.
    #[must_use]
    pub const fn identifier(self) -> u8 {
        self.packet[1]
    }

    /// Validate the declared packet with the existing AKA/AKA-prime parser.
    pub fn parse_aka(self) -> Result<EapAkaPacket<'a>, EapAkaError> {
        EapAkaPacket::parse(self.packet)
    }

    /// Validate the declared packet with the existing EAP-5G parser and bounds.
    ///
    /// `limits.max_packet_len` applies to the declared EAP packet, excluding
    /// the lower-layer padding already ignored by admission.
    pub fn parse_eap5g(self, limits: eap5g::Limits) -> Result<eap5g::Packet<'a>, eap5g::Error> {
        eap5g::Packet::parse(self.packet, limits)
    }
}

impl fmt::Debug for EapMethodPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EapMethodPacket").finish_non_exhaustive()
    }
}

/// Method-independent EAP admission (RFC 3748 sections 4, 4.1 and 4.2).
///
/// Request and Response carry unvalidated method packets; Success and Failure
/// carry only their identifier. All variants have value-free Debug output.
/// The existing [`crate::EapCode`] remains the Request/Response direction type
/// used by the method parsers.
#[derive(Debug, Clone, Copy)]
pub enum EapPacket<'a> {
    /// Code 1, with method validation left to the caller.
    Request(EapMethodPacket<'a>),
    /// Code 2, with method validation left to the caller.
    Response(EapMethodPacket<'a>),
    /// Code 3, Length 4 and no Data.
    Success(EapSuccess),
    /// Code 4, Length 4 and no Data.
    Failure(EapFailure),
}

impl<'a> EapPacket<'a> {
    /// Admit an EAP packet using only common header framing, without allocating.
    ///
    /// RFC 3748 section 4 requires octets beyond Length to be ignored as
    /// lower-layer padding. Length must fit within the received slice and
    /// include the four-octet header. Request/Response must also include a Type
    /// octet, but its value and all method contents remain unvalidated until
    /// [`EapMethodPacket::parse_aka`] or [`EapMethodPacket::parse_eap5g`] is called.
    ///
    /// Success/Failure require Length 4: any declared Data is rejected, even if
    /// zero-filled. Padding outside Length is distinct from declared Data and
    /// is never retained. Parsing does not correlate identifiers or decide
    /// whether authentication completed.
    pub fn parse(wire: &'a [u8]) -> Result<Self, EapPacketError> {
        if wire.len() < 4 {
            return Err(EapPacketError::TruncatedHeader);
        }
        let declared = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
        if declared < 4 {
            return Err(EapPacketError::InvalidLength);
        }
        if declared > wire.len() {
            return Err(EapPacketError::LengthMismatch);
        }
        match wire[0] {
            1 | 2 => {
                if declared < 5 {
                    return Err(EapPacketError::InvalidLength);
                }
                let packet = EapMethodPacket {
                    packet: &wire[..declared],
                };
                Ok(if wire[0] == 1 {
                    Self::Request(packet)
                } else {
                    Self::Response(packet)
                })
            }
            3 | 4 => {
                if declared != 4 {
                    return Err(EapPacketError::InvalidTerminalLength);
                }
                Ok(if wire[0] == 3 {
                    Self::Success(EapSuccess::new(wire[1]))
                } else {
                    Self::Failure(EapFailure::new(wire[1]))
                })
            }
            _ => Err(EapPacketError::UnsupportedCode),
        }
    }

    /// Return the EAP Identifier for caller-owned exchange correlation.
    #[must_use]
    pub const fn identifier(self) -> u8 {
        match self {
            Self::Request(packet) | Self::Response(packet) => packet.identifier(),
            Self::Success(packet) => packet.identifier(),
            Self::Failure(packet) => packet.identifier(),
        }
    }
}
