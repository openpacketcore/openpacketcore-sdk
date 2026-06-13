#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! PFCP protocol codec (TS 29.244) for OpenPacketCore.
//!
//! @spec 3GPP TS29244 R18
//! @req REQ-3GPP-TS29244-R18-001
//! @conformance v0 — see CONFORMANCE.md

pub mod ie;

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode, EncodeContext,
    EncodeError, EncodeErrorCode, OwnedDecode, SpecRef, ValidationLevel,
};

/// PFCP message type constants (TS 29.244 Table 7.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Heartbeat Request
    HeartbeatRequest = 1,
    /// Heartbeat Response
    HeartbeatResponse = 2,
    /// Association Setup Request
    AssociationSetupRequest = 5,
    /// Association Setup Response
    AssociationSetupResponse = 6,
    /// Association Release Request
    AssociationReleaseRequest = 9,
    /// Association Release Response
    AssociationReleaseResponse = 10,
    /// Session Establishment Request
    SessionEstablishmentRequest = 50,
    /// Session Establishment Response
    SessionEstablishmentResponse = 51,
    /// Session Modification Request
    SessionModificationRequest = 52,
    /// Session Modification Response
    SessionModificationResponse = 53,
    /// Session Deletion Request
    SessionDeletionRequest = 54,
    /// Session Deletion Response
    SessionDeletionResponse = 55,
    /// Session Report Request
    SessionReportRequest = 56,
    /// Session Report Response
    SessionReportResponse = 57,
}

/// PFCP message header (TS 29.244 Section 7.4.1).
///
/// Octet 1 bit layout per TS 29.244 §7.4.1.1: bits 8–6 carry the version,
/// bits 5–4 are spare, bit 3 is FO (Follow On), bit 2 is MP (message
/// priority present), and bit 1 is S (SEID present).
///
/// @spec 3GPP TS29244 R18 7.4.1
/// @req REQ-3GPP-TS29244-R18-7.4.1-001
/// @conformance v0
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Version (must be 1).
    pub version: u8,
    /// Spare bits 5–4 of octet 1 (must be 0 in strict mode).
    pub spare: u8,
    /// FO flag, octet 1 bit 3 (must be 0 in strict mode).
    pub fo: bool,
    /// MP flag, octet 1 bit 2 (message priority present).
    pub mp: bool,
    /// S flag, octet 1 bit 1 (SEID present).
    pub s: bool,
    /// Message type.
    pub message_type: u8,
    /// Message length (excluding the first 4 octets).
    pub length: u16,
    /// SEID (present if S flag is set).
    pub seid: Option<u64>,
    /// Sequence number (24-bit).
    pub sequence_number: u32,
    /// Message priority (bits 8–5 of the final header octet, when MP is set).
    /// Encoded as `message_priority.unwrap_or(0)` if `mp` is true.
    pub message_priority: Option<u8>,
    /// Final header octet spare bits. When `mp` is set this holds only the
    /// low nibble (bits 4–1); otherwise the entire octet.
    pub spare_octet: u8,
}

impl Header {
    /// Header size in octets when SEID is present.
    const SIZE_WITH_SEID: usize = 16;
    /// Header size in octets when SEID is absent.
    const SIZE_WITHOUT_SEID: usize = 8;

    /// Compute the on-wire header size.
    pub fn wire_len(&self) -> usize {
        if self.s {
            Self::SIZE_WITH_SEID
        } else {
            Self::SIZE_WITHOUT_SEID
        }
    }
}

/// Decode a PFCP header from a byte slice.
///
/// @spec 3GPP TS29244 R18 7.4.1
/// @req REQ-3GPP-TS29244-R18-7.4.1-002
/// @conformance v0
fn decode_header(input: &[u8], ctx: DecodeContext) -> DecodeResult<'_, Header> {
    let spec_ref = SpecRef::new("3gpp", "TS29244", "7.4.1");
    if input.len() < Header::SIZE_WITHOUT_SEID {
        return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec_ref));
    }

    // TS 29.244 §7.4.1.1: bits 8-6 version, 5-4 spare, 3 FO, 2 MP, 1 S.
    let b1 = input[0];
    let version = (b1 >> 5) & 0x07;
    let spare = (b1 >> 3) & 0x03;
    let fo = (b1 & 0x04) != 0;
    let mp = (b1 & 0x02) != 0;
    let s = (b1 & 0x01) != 0;

    if version != 1 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidEnumValue {
                field: "version",
                value: version as u64,
            },
            0,
        )
        .with_spec_ref(spec_ref.clone()));
    }

    if ctx.validation_level == ValidationLevel::Strict
        || ctx.validation_level == ValidationLevel::ProcedureAware
    {
        if spare != 0 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "spare bits must be zero",
                },
                0,
            )
            .with_spec_ref(spec_ref.clone()));
        }
        if fo {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "FO flag must be zero",
                },
                0,
            )
            .with_spec_ref(spec_ref.clone()));
        }
    }

    let message_type = input[1];
    let length = u16::from_be_bytes([input[2], input[3]]);

    let total_len = if s {
        Header::SIZE_WITH_SEID
    } else {
        Header::SIZE_WITHOUT_SEID
    };

    if input.len() < total_len {
        return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec_ref.clone()));
    }

    let (seid, seq_bytes, last_octet) = if s {
        let seid = u64::from_be_bytes([
            input[4], input[5], input[6], input[7], input[8], input[9], input[10], input[11],
        ]);
        let seq = u32::from_be_bytes([0, input[12], input[13], input[14]]);
        (Some(seid), seq, input[15])
    } else {
        let seq = u32::from_be_bytes([0, input[4], input[5], input[6]]);
        (None, seq, input[7])
    };

    // The final header octet carries the message priority in its high nibble
    // when MP is set; otherwise the whole octet is spare.
    let (message_priority, spare_octet) = if mp {
        (Some(last_octet >> 4), last_octet & 0x0F)
    } else {
        (None, last_octet)
    };

    let header = Header {
        version,
        spare,
        fo,
        mp,
        s,
        message_type,
        length,
        seid,
        sequence_number: seq_bytes & 0x00FF_FFFF,
        message_priority,
        spare_octet,
    };

    Ok((&input[total_len..], header))
}

/// Encode a PFCP header into a buffer.
///
/// @spec 3GPP TS29244 R18 7.4.1
/// @req REQ-3GPP-TS29244-R18-7.4.1-003
/// @conformance v0
fn encode_header(
    header: &Header,
    dst: &mut BytesMut,
    _ctx: EncodeContext,
) -> Result<(), EncodeError> {
    // TS 29.244 §7.4.1.1: bits 8-6 version, 5-4 spare, 3 FO, 2 MP, 1 S.
    let mut b1 = (header.version & 0x07) << 5;
    b1 |= (header.spare & 0x03) << 3;
    if header.fo {
        b1 |= 0x04;
    }
    if header.mp {
        b1 |= 0x02;
    }
    if header.s {
        b1 |= 0x01;
    }

    dst.put_u8(b1);
    dst.put_u8(header.message_type);
    dst.put_u16(header.length);

    if let Some(seid) = header.seid {
        dst.put_u64(seid);
    }

    let seq = header.sequence_number & 0x00FF_FFFF;
    dst.put_u8(((seq >> 16) & 0xFF) as u8);
    dst.put_u8(((seq >> 8) & 0xFF) as u8);
    dst.put_u8((seq & 0xFF) as u8);

    let last_octet = if header.mp {
        ((header.message_priority.unwrap_or(0) & 0x0F) << 4) | (header.spare_octet & 0x0F)
    } else {
        header.spare_octet
    };
    dst.put_u8(last_octet);

    Ok(())
}

/// PFCP Information Element type constants (TS 29.244 Table 7.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IeType {
    /// Create PDR
    CreatePdr = 1,
    /// PDI
    Pdi = 2,
    /// Create FAR
    CreateFar = 3,
    /// Forwarding Parameters
    ForwardingParameters = 4,
    /// Create URR
    CreateUrr = 6,
    /// Create QER
    CreateQer = 7,
    /// Created PDR
    CreatedPdr = 8,
    /// Update PDR
    UpdatePdr = 9,
    /// Update FAR
    UpdateFar = 10,
    /// Update Forwarding Parameters
    UpdateForwardingParameters = 11,
    /// Update URR
    UpdateUrr = 13,
    /// Update QER
    UpdateQer = 14,
    /// Remove PDR
    RemovePdr = 15,
    /// Remove FAR
    RemoveFar = 16,
    /// Remove URR
    RemoveUrr = 17,
    /// Remove QER
    RemoveQer = 18,
    /// Cause
    Cause = 19,
    /// Source Interface
    SourceInterface = 20,
    /// F-TEID
    FTeid = 21,
    /// Network Instance
    NetworkInstance = 22,
    /// Gate Status
    GateStatus = 25,
    /// MBR
    Mbr = 26,
    /// GBR
    Gbr = 27,
    /// Precedence
    Precedence = 29,
    /// Reporting Triggers
    ReportingTriggers = 37,
    /// Report Type
    ReportType = 39,
    /// Destination Interface
    DestinationInterface = 42,
    /// Apply Action
    ApplyAction = 44,
    /// PDR ID
    PdrId = 56,
    /// F-SEID
    FSeid = 57,
    /// Node ID
    NodeId = 60,
    /// Measurement Method
    MeasurementMethod = 62,
    /// URR ID
    UrrId = 81,
    /// Outer Header Creation
    OuterHeaderCreation = 84,
    /// Outer Header Removal
    OuterHeaderRemoval = 95,
    /// Recovery Time Stamp
    RecoveryTimeStamp = 96,
    /// UE IP Address
    UeIpAddress = 93,
    /// FAR ID
    FarId = 108,
    /// QER ID
    QerId = 109,
    /// QoS Flow Identifier
    Qfi = 124,
}

/// A generic PFCP IE with type/length framing and raw byte preservation.
///
/// Per TS 29.244 §8.1.1 the Length field excludes the first four octets
/// (Type and Length) but INCLUDES the two Enterprise ID octets present on
/// vendor-specific IEs (type ≥ 32768).
///
/// @spec 3GPP TS29244 R18 8.1.1
/// @req REQ-3GPP-TS29244-R18-8.1.1-001
/// @conformance v0
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InformationElement {
    /// IE type.
    pub ie_type: u16,
    /// Enterprise ID (0 for standard IEs; meaningful for type ≥ 32768).
    pub enterprise_id: u16,
    /// Raw IE value bytes (excluding the Enterprise ID octets).
    pub value: Bytes,
}

impl InformationElement {
    /// Decode a single IE from the input buffer.
    ///
    /// @spec 3GPP TS29244 R18 8.1.1
    /// @req REQ-3GPP-TS29244-R18-8.1.1-002
    /// @conformance v0
    pub fn decode(input: &[u8]) -> DecodeResult<'_, Self> {
        let spec_ref = SpecRef::new("3gpp", "TS29244", "8.1.1");
        if input.len() < 4 {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec_ref));
        }

        let ie_type = u16::from_be_bytes([input[0], input[1]]);
        let length = u16::from_be_bytes([input[2], input[3]]) as usize;

        let total_len = match 4usize.checked_add(length) {
            Some(l) => l,
            None => {
                return Err(
                    DecodeError::new(DecodeErrorCode::LengthOverflow, 2).with_spec_ref(spec_ref)
                )
            }
        };

        if input.len() < total_len {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec_ref));
        }

        let (enterprise_id, value_start) = if ie_type >= 0x8000 {
            // The Length field counts the Enterprise ID octets (§8.1.1).
            if length < 2 {
                return Err(DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "vendor-specific IE length must include enterprise id",
                    },
                    2,
                )
                .with_spec_ref(spec_ref));
            }
            (u16::from_be_bytes([input[4], input[5]]), 6usize)
        } else {
            (0, 4usize)
        };

        let value = Bytes::copy_from_slice(&input[value_start..total_len]);

        Ok((
            &input[total_len..],
            Self {
                ie_type,
                enterprise_id,
                value,
            },
        ))
    }

    /// Encode this IE into a buffer.
    ///
    /// @spec 3GPP TS29244 R18 8.1.1
    /// @req REQ-3GPP-TS29244-R18-8.1.1-003
    /// @conformance v0
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        let spec_ref = SpecRef::new("3gpp", "TS29244", "8.1.1");
        let mut length = self.value.len();
        if self.ie_type >= 0x8000 {
            length = length
                .checked_add(2)
                .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref.clone()))?;
        }
        let length_u16 = u16::try_from(length)
            .map_err(|_| EncodeError::length_overflow().with_spec_ref(spec_ref.clone()))?;

        dst.put_u16(self.ie_type);
        dst.put_u16(length_u16);
        if self.ie_type >= 0x8000 {
            dst.put_u16(self.enterprise_id);
        }
        dst.put_slice(&self.value);

        Ok(())
    }

    /// On-wire length of this IE.
    pub fn wire_len(&self) -> usize {
        let header_len = if self.ie_type >= 0x8000 { 6 } else { 4 };
        header_len + self.value.len()
    }

    /// Build a raw [`InformationElement`] from a typed IE.
    ///
    /// The typed value is encoded and wrapped with the correct type code and
    /// zero enterprise id. This lets consumers compose responses directly from
    /// the typed layer instead of hand-building raw value bytes.
    ///
    /// @spec 3GPP TS29244 R18 8.1.1
    /// @req REQ-3GPP-TS29244-R18-8.1.1-004
    ///
    /// # Example
    ///
    /// ```rust
    /// use opc_proto_pfcp::ie::{Cause, CauseValue, TypedIe};
    /// use opc_proto_pfcp::InformationElement;
    ///
    /// let typed = TypedIe::Cause(Cause {
    ///     value: CauseValue::RequestAccepted,
    /// });
    /// let raw = InformationElement::from_typed(&typed).expect("encodes");
    /// assert_eq!(raw.ie_type, 19);
    /// assert_eq!(raw.value.as_ref(), &[1]);
    /// ```
    pub fn from_typed(typed: &crate::ie::TypedIe) -> Result<Self, EncodeError> {
        match typed {
            crate::ie::TypedIe::Raw(raw) => Ok(raw.clone()),
            other => {
                let value = other.encode_value()?;
                Ok(Self {
                    ie_type: typed.ie_type(),
                    enterprise_id: 0,
                    value,
                })
            }
        }
    }
}

/// A borrowed PFCP message.
///
/// @spec 3GPP TS29244 R18 7.4.1
/// @req REQ-3GPP-TS29244-R18-7.4.1-004
/// @conformance v0
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// Parsed header.
    pub header: Header,
    /// Information Elements.
    pub ies: Vec<InformationElement>,
    /// Bytes beyond the message boundary declared by the header Length
    /// field (e.g. a following PDU in the same buffer). Also returned as
    /// the unconsumed remainder from [`BorrowDecode::decode`].
    pub tail: &'a [u8],
}

impl<'a> BorrowDecode<'a> for Message<'a> {
    /// Decode a PFCP message from a byte slice.
    ///
    /// The header Length field is honored: the message ends `4 + length`
    /// octets in; any following bytes are returned as the unconsumed
    /// remainder (and mirrored in [`Message::tail`]). Inputs shorter than
    /// the declared length are rejected as truncated.
    ///
    /// @spec 3GPP TS29244 R18 7.4.1
    /// @req REQ-3GPP-TS29244-R18-7.4.1-005
    /// @conformance v0
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        let spec_ref = SpecRef::new("3gpp", "TS29244", "7.4.1");
        if input.len() > ctx.max_message_len {
            return Err(
                DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 0).with_spec_ref(spec_ref)
            );
        }

        let (_, header) = decode_header(input, ctx)?;

        // The Length field excludes the first 4 octets (§7.4.1).
        let msg_end = match 4usize.checked_add(header.length as usize) {
            Some(l) => l,
            None => {
                return Err(
                    DecodeError::new(DecodeErrorCode::LengthOverflow, 2).with_spec_ref(spec_ref)
                )
            }
        };
        if msg_end > input.len() {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 2).with_spec_ref(spec_ref));
        }
        if msg_end < header.wire_len() {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "message length shorter than header",
                },
                2,
            )
            .with_spec_ref(spec_ref));
        }

        let region = &input[header.wire_len()..msg_end];
        let mut ies = Vec::new();
        let mut offset = 0usize;
        let mut ie_count = 0usize;

        while offset < region.len() {
            ie_count += 1;
            if ie_count > ctx.max_ies {
                return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                    .with_spec_ref(spec_ref));
            }

            let (remaining, ie) = InformationElement::decode(&region[offset..])?;
            ies.push(ie);
            offset = region.len() - remaining.len();
        }

        let tail = &input[msg_end..];
        Ok((tail, Self { header, ies, tail }))
    }
}

impl Message<'_> {
    fn encoded_lens(&self) -> Result<(usize, u16), EncodeError> {
        let spec_ref = SpecRef::new("3gpp", "TS29244", "7.4.1");
        let ie_len: usize = self.ies.iter().try_fold(0usize, |acc, ie| {
            acc.checked_add(ie.wire_len())
                .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref.clone()))
        })?;

        let total_len = self
            .header
            .wire_len()
            .checked_add(ie_len)
            .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref.clone()))?;

        let len_u16 = u16::try_from(total_len.checked_sub(4).ok_or_else(|| {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "message length underflow",
            })
        })?)
        .map_err(|_| EncodeError::length_overflow().with_spec_ref(spec_ref))?;

        Ok((total_len, len_u16))
    }
}

impl Encode for Message<'_> {
    /// Encode this message, recomputing the header Length field.
    ///
    /// @spec 3GPP TS29244 R18 7.4.1
    /// @req REQ-3GPP-TS29244-R18-7.4.1-006
    /// @conformance v0
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let (_, len_u16) = self.encoded_lens()?;
        let mut header = self.header.clone();
        header.length = len_u16;

        encode_header(&header, dst, ctx)?;
        for ie in &self.ies {
            ie.encode(dst)?;
        }

        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        let (total_len, _) = self.encoded_lens()?;
        Ok(total_len)
    }
}

/// An owned PFCP message.
///
/// @spec 3GPP TS29244 R18 7.4.1
/// @req REQ-3GPP-TS29244-R18-7.4.1-007
/// @conformance v0
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedMessage {
    /// Parsed header.
    pub header: Header,
    /// Information Elements.
    pub ies: Vec<InformationElement>,
}

impl OwnedMessage {
    fn as_borrowed(&self) -> Message<'_> {
        Message {
            header: self.header.clone(),
            ies: self.ies.clone(),
            tail: &[],
        }
    }
}

impl OwnedDecode for OwnedMessage {
    /// Decode an owned PFCP message.
    ///
    /// @spec 3GPP TS29244 R18 7.4.1
    /// @req REQ-3GPP-TS29244-R18-7.4.1-008
    /// @conformance v0
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (_, msg) = Message::decode(&input, ctx)?;
        Ok(Self {
            header: msg.header,
            ies: msg.ies,
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

/// Build a Heartbeat Request message.
///
/// @spec 3GPP TS29244 R18 7.4.2
/// @req REQ-3GPP-TS29244-R18-7.4.2-004
/// @conformance v0
pub fn heartbeat_request(seq: u32) -> OwnedMessage {
    OwnedMessage {
        header: Header {
            version: 1,
            spare: 0,
            fo: false,
            mp: false,
            s: false,
            message_type: MessageType::HeartbeatRequest as u8,
            length: 0,
            seid: None,
            sequence_number: seq,
            message_priority: None,
            spare_octet: 0,
        },
        ies: Vec::new(),
    }
}

/// Build a Heartbeat Response message.
///
/// @spec 3GPP TS29244 R18 7.4.2
/// @req REQ-3GPP-TS29244-R18-7.4.2-005
/// @conformance v0
pub fn heartbeat_response(seq: u32) -> OwnedMessage {
    OwnedMessage {
        header: Header {
            version: 1,
            spare: 0,
            fo: false,
            mp: false,
            s: false,
            message_type: MessageType::HeartbeatResponse as u8,
            length: 0,
            seid: None,
            sequence_number: seq,
            message_priority: None,
            spare_octet: 0,
        },
        ies: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn encode_owned(msg: &OwnedMessage) -> Bytes {
        let mut buf = BytesMut::new();
        msg.encode(&mut buf, EncodeContext::default()).unwrap();
        buf.freeze()
    }

    /// decode(bytes) → encode must reproduce `bytes` exactly.
    fn assert_byte_exact_roundtrip(bytes: &[u8]) {
        let decoded =
            OwnedMessage::decode_owned(Bytes::copy_from_slice(bytes), DecodeContext::default())
                .unwrap();
        assert_eq!(
            &encode_owned(&decoded)[..],
            bytes,
            "round-trip not byte-exact"
        );
    }

    #[test]
    fn test_heartbeat_request_roundtrip() {
        let msg = heartbeat_request(42);
        let bytes = encode_owned(&msg);
        let decoded = OwnedMessage::decode_owned(bytes.clone(), DecodeContext::default()).unwrap();
        assert_eq!(
            decoded.header.message_type,
            MessageType::HeartbeatRequest as u8
        );
        assert_eq!(decoded.header.sequence_number, 42);
        assert!(decoded.ies.is_empty());
        assert_eq!(encode_owned(&decoded), bytes);
    }

    #[test]
    fn test_heartbeat_response_roundtrip() {
        let msg = heartbeat_response(99);
        let bytes = encode_owned(&msg);
        let decoded = OwnedMessage::decode_owned(bytes.clone(), DecodeContext::default()).unwrap();
        assert_eq!(
            decoded.header.message_type,
            MessageType::HeartbeatResponse as u8
        );
        assert_eq!(decoded.header.sequence_number, 99);
        assert!(decoded.ies.is_empty());
        assert_eq!(encode_owned(&decoded), bytes);
    }

    /// Octet-1 flag layout per TS 29.244 §7.4.1.1, asserted against
    /// hand-authored spec bytes (NOT against this codec's own encoder):
    /// 0x21 = version 1 | S; SEID-bearing 16-octet header.
    #[test]
    fn test_spec_byte_layout_seid_message() {
        let bytes: &[u8] = &[
            0x21, 0x32, 0x00, 0x0C, // version 1, S=1, Session Est Req, length 12
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, // SEID
            0x00, 0x00, 0x07, // sequence 7
            0x00, // spare
        ];
        let decoded =
            OwnedMessage::decode_owned(Bytes::copy_from_slice(bytes), DecodeContext::default())
                .unwrap();
        assert!(decoded.header.s);
        assert!(!decoded.header.mp);
        assert!(!decoded.header.fo);
        assert_eq!(decoded.header.seid, Some(0x1234_5678_9ABC_DEF0));
        assert_eq!(decoded.header.sequence_number, 7);
        assert_byte_exact_roundtrip(bytes);
    }

    /// 0x23 = version 1 | MP | S; message priority lives in the high nibble
    /// of the final header octet (TS 29.244 §7.4.1).
    #[test]
    fn test_spec_byte_layout_message_priority() {
        let bytes: &[u8] = &[
            0x23, 0x32, 0x00, 0x0C, // version 1, MP=1, S=1
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, // SEID
            0x00, 0x00, 0x07, // sequence 7
            0x50, // priority 5, spare nibble 0
        ];
        let decoded =
            OwnedMessage::decode_owned(Bytes::copy_from_slice(bytes), DecodeContext::default())
                .unwrap();
        assert!(decoded.header.mp);
        assert_eq!(decoded.header.message_priority, Some(5));
        assert_eq!(decoded.header.spare_octet, 0);
        assert_byte_exact_roundtrip(bytes);
    }

    #[test]
    fn test_message_with_unknown_ie_roundtrip() {
        let mut msg = heartbeat_request(1);
        msg.ies.push(InformationElement {
            ie_type: 9999,
            enterprise_id: 0,
            value: Bytes::from_static(b"hello"),
        });
        let bytes = encode_owned(&msg);
        let decoded = OwnedMessage::decode_owned(bytes.clone(), DecodeContext::default()).unwrap();
        assert_eq!(decoded.ies.len(), 1);
        assert_eq!(decoded.ies[0].ie_type, 9999);
        assert_eq!(&decoded.ies[0].value[..], b"hello");
        assert_byte_exact_roundtrip(&bytes);
    }

    /// Vendor-specific IE per §8.1.1: Length counts the Enterprise ID octets,
    /// which sit between the Length field and the value.
    #[test]
    fn test_enterprise_ie_spec_bytes_roundtrip() {
        let bytes: &[u8] = &[
            0x20, 0x01, 0x00,
            0x0D, // version 1, Heartbeat Req, length 13 (4 seq/spare + 9 IE)
            0x00, 0x00, 0x01, 0x00, // sequence 1, spare
            0x80, 0x01, // vendor IE type 0x8001
            0x00, 0x05, // length 5 = enterprise id (2) + value (3)
            0x00, 0x42, // enterprise id 0x42
            0x61, 0x62, 0x63, // value "abc"
        ];
        let decoded =
            OwnedMessage::decode_owned(Bytes::copy_from_slice(bytes), DecodeContext::default())
                .unwrap();
        assert_eq!(decoded.ies.len(), 1);
        assert_eq!(decoded.ies[0].ie_type, 0x8001);
        assert_eq!(decoded.ies[0].enterprise_id, 0x42);
        assert_eq!(&decoded.ies[0].value[..], b"abc");
        assert_byte_exact_roundtrip(bytes);
    }

    #[test]
    fn test_message_with_seid_roundtrip() {
        let msg = OwnedMessage {
            header: Header {
                version: 1,
                spare: 0,
                fo: false,
                mp: false,
                s: true,
                message_type: MessageType::SessionEstablishmentRequest as u8,
                length: 0,
                seid: Some(0x123456789ABCDEF0),
                sequence_number: 7,
                message_priority: None,
                spare_octet: 0,
            },
            ies: Vec::new(),
        };
        let bytes = encode_owned(&msg);
        // S flag is octet-1 bit 1 per the spec.
        assert_eq!(bytes[0], 0x21);
        let decoded = OwnedMessage::decode_owned(bytes.clone(), DecodeContext::default()).unwrap();
        assert_eq!(decoded.header.seid, Some(0x123456789ABCDEF0));
        assert_eq!(decoded.header.sequence_number, 7);
        assert!(decoded.header.s);
        assert_byte_exact_roundtrip(&bytes);
    }

    /// Trailing bytes beyond the declared message length are returned as the
    /// unconsumed remainder, enabling multiple PDUs per buffer.
    #[test]
    fn test_trailing_bytes_returned_as_tail() {
        let mut bytes = encode_owned(&heartbeat_request(3)).to_vec();
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let (rest, msg) = Message::decode(&bytes, DecodeContext::default()).unwrap();
        assert_eq!(rest, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(msg.tail, rest);
        assert!(msg.ies.is_empty());
    }

    #[test]
    fn test_truncated_header_rejected() {
        let result =
            OwnedMessage::decode_owned(Bytes::from_static(&[0x20, 0x01]), DecodeContext::default());
        assert!(result.is_err());
    }

    /// A header Length field claiming more payload than the input carries
    /// must be rejected as truncated, not silently re-bounded.
    #[test]
    fn test_lying_length_field_rejected() {
        let result = OwnedMessage::decode_owned(
            Bytes::from_static(&[0x20, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00]),
            DecodeContext::default(),
        );
        assert!(result.is_err());
    }

    /// A SEID-bearing header whose Length field is smaller than its own
    /// SEID/sequence octets is structurally invalid.
    #[test]
    fn test_length_shorter_than_header_rejected() {
        let result = OwnedMessage::decode_owned(
            Bytes::from_static(&[
                0x21, 0x32, 0x00, 0x04, // S=1 but length 4 < 12 header octets after length
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x00, 0x00, 0x07, 0x00,
            ]),
            DecodeContext::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_ie_value_rejected() {
        // Message claims a 5-octet IE value but only 1 octet follows.
        let result = OwnedMessage::decode_owned(
            Bytes::from_static(&[
                0x20, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, // header, length 9
                0x27, 0x0F, 0x00, 0x05, 0xAB, // IE claims length 5, has 1
            ]),
            DecodeContext::default(),
        );
        assert!(result.is_err());
    }

    /// Vendor-specific IEs must carry at least the 2-octet Enterprise ID.
    #[test]
    fn test_enterprise_ie_short_length_rejected() {
        let result = OwnedMessage::decode_owned(
            Bytes::from_static(&[
                0x20, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, // header, length 9
                0x80, 0x01, 0x00, 0x01, 0xAB, // vendor IE with length 1 (< 2)
            ]),
            DecodeContext::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_version_mismatch_rejected() {
        let result = OwnedMessage::decode_owned(
            Bytes::from_static(&[0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]),
            DecodeContext::default(),
        );
        assert!(result.is_err());
    }

    quickcheck::quickcheck! {
        /// Property: any IE (standard or vendor-specific) survives
        /// encode → decode → encode byte-exactly.
        fn prop_ie_roundtrip_byte_exact(ie_type: u16, enterprise_id: u16, value: Vec<u8>) -> bool {
            let value = &value[..value.len().min(60_000)];
            let ie = InformationElement {
                ie_type,
                enterprise_id: if ie_type >= 0x8000 { enterprise_id } else { 0 },
                value: Bytes::copy_from_slice(value),
            };

            let mut buf = BytesMut::new();
            if ie.encode(&mut buf).is_err() {
                return false;
            }
            let bytes = buf.freeze();

            let (rest, decoded) = match InformationElement::decode(&bytes) {
                Ok(v) => v,
                Err(_) => return false,
            };
            if !rest.is_empty() || decoded != ie {
                return false;
            }

            let mut buf2 = BytesMut::new();
            if decoded.encode(&mut buf2).is_err() {
                return false;
            }
            buf2.freeze() == bytes
        }
    }
}
