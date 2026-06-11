#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! GTP-U protocol crate for OpenPacketCore.
//!
//! @spec 3GPP TS29281 R18 5.1
//! @req REQ-3GPP-TS29281-R18-5.1-001
//! @conformance full

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode, EncodeContext,
    EncodeError, EncodeErrorCode, OwnedDecode, SpecRef, ToOwnedPdu, ValidationLevel,
};

fn validation_strictness(level: ValidationLevel) -> u8 {
    match level {
        ValidationLevel::HeaderOnly => 0,
        ValidationLevel::Structural => 1,
        ValidationLevel::Strict => 2,
        ValidationLevel::ProcedureAware => 3,
    }
}

/// GTP-U Header fields (TS 29.281 Section 5.1).
///
/// @spec 3GPP TS29281 R18 5.1
/// @req REQ-3GPP-TS29281-R18-5.1-002
/// @conformance full
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtpuHeader {
    /// GTP-U version (must be 1).
    pub version: u8,
    /// Protocol type flag (must be true for GTP).
    pub protocol_type: bool,
    /// Reserved bit (must be 0 in strict mode).
    pub reserved: u8,
    /// Extension header flag.
    pub ext_hdr_flag: bool,
    /// Sequence number flag.
    pub seq_num_flag: bool,
    /// N-PDU number flag.
    pub npdu_num_flag: bool,
    /// GTP-U message type.
    pub message_type: u8,
    /// Length of the payload plus optional fields.
    pub length: u16,
    /// Tunnel Endpoint Identifier.
    pub teid: u32,
    /// Parsed sequence number, if present.
    pub sequence_number: Option<u16>,
    /// Parsed N-PDU number, if present.
    pub npdu_number: Option<u8>,
    /// Type of the next extension header, if any.
    pub next_ext_type: Option<u8>,
    /// Raw sequence number before flag interpretation.
    pub raw_sequence_number: Option<u16>,
    /// Raw N-PDU number before flag interpretation.
    pub raw_npdu_number: Option<u8>,
    /// Raw next extension type before flag interpretation.
    pub raw_next_ext_type: Option<u8>,
}

/// A zero-copy borrowed view of a GTP-U message.
///
/// @spec 3GPP TS29281 R18 5.1
/// @req REQ-3GPP-TS29281-R18-5.1-003
/// @conformance full
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtpuMessage<'a> {
    /// Parsed GTP-U header.
    pub header: GtpuHeader,
    /// Raw extension header bytes.
    pub raw_extension_headers: &'a [u8],
    /// GTP-U payload.
    pub payload: &'a [u8],
}

impl<'a> GtpuMessage<'a> {
    /// Walk and iterate over the extension headers lazily.
    ///
    /// @spec 3GPP TS29281 R18 5.2.1
    /// @req REQ-3GPP-TS29281-R18-5.2.1-001
    /// @conformance full
    pub fn extensions(&self) -> GtpuExtensionHeaderIterator<'a> {
        GtpuExtensionHeaderIterator::new(
            self.raw_extension_headers,
            self.header.next_ext_type.unwrap_or(0),
        )
    }
}

/// An owned representation of a GTP-U message utilizing Bytes for zero-allocation copy of payload/headers.
///
/// @spec 3GPP TS29281 R18 5.1
/// @req REQ-3GPP-TS29281-R18-5.1-004
/// @conformance full
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedGtpuMessage {
    /// Parsed GTP-U header.
    pub header: GtpuHeader,
    /// Raw extension header bytes.
    pub raw_extension_headers: Bytes,
    /// GTP-U payload.
    pub payload: Bytes,
}

impl OwnedGtpuMessage {
    /// Walk and iterate over the extension headers lazily.
    ///
    /// @spec 3GPP TS29281 R18 5.2.1
    /// @req REQ-3GPP-TS29281-R18-5.2.1-002
    /// @conformance full
    pub fn extensions(&self) -> GtpuExtensionHeaderIterator<'_> {
        GtpuExtensionHeaderIterator::new(
            &self.raw_extension_headers,
            self.header.next_ext_type.unwrap_or(0),
        )
    }
}

/// GTP-U Extension Header representing a single extension header.
///
/// @spec 3GPP TS29281 R18 5.2.1
/// @req REQ-3GPP-TS29281-R18-5.2.1-003
/// @conformance full
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtpuExtensionHeader<'a> {
    /// Extension header type identifier.
    pub ext_type: u8,
    /// Extension header content bytes.
    pub content: &'a [u8],
    /// Type of the next extension header (0 if none).
    pub next_ext_type: u8,
}

/// Lazy, zero-allocation iterator over GTP-U Extension Headers.
///
/// @spec 3GPP TS29281 R18 5.2.1
/// @req REQ-3GPP-TS29281-R18-5.2.1-004
/// @conformance full
pub struct GtpuExtensionHeaderIterator<'a> {
    /// Remaining extension header bytes.
    buffer: &'a [u8],
    /// Type of the next extension header to parse.
    next_ext_type: u8,
}

impl<'a> GtpuExtensionHeaderIterator<'a> {
    /// Create a new iterator over extension headers.
    pub fn new(buffer: &'a [u8], first_ext_type: u8) -> Self {
        Self {
            buffer,
            next_ext_type: first_ext_type,
        }
    }
}

impl<'a> Iterator for GtpuExtensionHeaderIterator<'a> {
    type Item = Result<GtpuExtensionHeader<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_ext_type == 0 {
            return None;
        }

        if self.buffer.is_empty() {
            self.next_ext_type = 0;
            return Some(Err(DecodeError::new(DecodeErrorCode::Truncated, 0)));
        }

        let ext_len_units = self.buffer[0] as usize;
        if ext_len_units == 0 {
            self.next_ext_type = 0;
            return Some(Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "extension header units is zero",
                },
                0,
            )));
        }

        let ext_len_bytes = match ext_len_units.checked_mul(4) {
            Some(len) => len,
            None => {
                self.next_ext_type = 0;
                return Some(Err(DecodeError::new(DecodeErrorCode::LengthOverflow, 0)));
            }
        };

        if self.buffer.len() < ext_len_bytes {
            self.next_ext_type = 0;
            return Some(Err(DecodeError::new(DecodeErrorCode::Truncated, 0)));
        }

        let ext_type = self.next_ext_type;
        let content = &self.buffer[1..ext_len_bytes - 1];
        let next_ext = self.buffer[ext_len_bytes - 1];

        self.buffer = &self.buffer[ext_len_bytes..];
        self.next_ext_type = next_ext;

        Some(Ok(GtpuExtensionHeader {
            ext_type,
            content,
            next_ext_type: next_ext,
        }))
    }
}

/// 5G PDU Session Container (QoS Flow Identifier) extension header.
///
/// @spec 3GPP TS29281 R18 5.2.2.7
/// @req REQ-3GPP-TS29281-R18-5.2.2.7-001
/// @conformance full
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionContainer {
    /// PDU type: 0 = DL, 1 = UL.
    pub pdu_type: u8,
    /// 6-bit QoS Flow Identifier.
    pub qfi: u8,
    /// Paging Policy Indicator (DL only).
    pub ppi: Option<u8>,
    /// Reflective QoS Indicator (DL only).
    pub rqi: bool,
}

impl PduSessionContainer {
    /// Decode a PduSessionContainer from a GtpuExtensionHeader.
    ///
    /// @spec 3GPP TS29281 R18 5.2.2.7
    /// @req REQ-3GPP-TS29281-R18-5.2.2.7-002
    /// @conformance full
    pub fn decode(ext: &GtpuExtensionHeader<'_>) -> Result<Self, DecodeError> {
        let spec_ref = SpecRef::new("3gpp", "TS29281", "5.2.2.7");
        if ext.ext_type != 0x85 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "extension type is not PDU Session Container",
                },
                0,
            )
            .with_spec_ref(spec_ref));
        }

        let content = ext.content;
        if content.is_empty() {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec_ref));
        }

        let pdu_type = (content[0] >> 4) & 0x0F;
        if pdu_type == 0 {
            // DL PDU Session Information
            if content.len() < 2 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, 1).with_spec_ref(spec_ref));
            }
            let ppp = (content[1] & 0x80) != 0;
            let rqi = (content[1] & 0x40) != 0;
            let qfi = content[1] & 0x3F;
            let ppi = if ppp {
                if content.len() < 3 {
                    return Err(DecodeError::new(
                        DecodeErrorCode::Structural {
                            reason: "Paging Policy Indicator missing despite PPP flag",
                        },
                        1,
                    )
                    .with_spec_ref(spec_ref));
                }
                Some(content[2] & 0x07)
            } else {
                None
            };
            Ok(Self {
                pdu_type,
                qfi,
                ppi,
                rqi,
            })
        } else if pdu_type == 1 {
            // UL PDU Session Information
            if content.len() < 2 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, 1).with_spec_ref(spec_ref));
            }
            let qfi = content[1] & 0x3F;
            Ok(Self {
                pdu_type,
                qfi,
                ppi: None,
                rqi: false,
            })
        } else {
            // Other/Unknown PDU Session Container types
            if content.len() < 2 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, 1).with_spec_ref(spec_ref));
            }
            let qfi = content[1] & 0x3F;
            Ok(Self {
                pdu_type,
                qfi,
                ppi: None,
                rqi: false,
            })
        }
    }

    /// Encode the PduSessionContainer into standard extension header content bytes.
    ///
    /// @spec 3GPP TS29281 R18 5.2.2.7
    /// @req REQ-3GPP-TS29281-R18-5.2.2.7-003
    /// @conformance full
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        let octet2 = (self.pdu_type & 0x0F) << 4;
        content.push(octet2);
        if self.pdu_type == 0 {
            let mut octet3 = self.qfi & 0x3F;
            if self.ppi.is_some() {
                octet3 |= 0x80; // PPP = 1
            }
            if self.rqi {
                octet3 |= 0x40; // RQI = 1
            }
            content.push(octet3);
            if let Some(ppi) = self.ppi {
                content.push(ppi & 0x07);
            }
        } else {
            let octet3 = self.qfi & 0x3F;
            content.push(octet3);
        }

        // Pad to ensure total size of extension header is multiple of 4 octets.
        // Total size = 1 (len) + content.len() + 1 (next_ext) = content.len() + 2.
        let rem = (content.len() + 2) % 4;
        if rem != 0 {
            let padding_needed = 4 - rem;
            content.resize(content.len() + padding_needed, 0);
        }
        content
    }
}

impl<'a> BorrowDecode<'a> for GtpuMessage<'a> {
    /// Eagerly validates and decodes GtpuMessage from a byte slice.
    ///
    /// @spec 3GPP TS29281 R18 5.1
    /// @req REQ-3GPP-TS29281-R18-5.1-005
    /// @conformance full
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        let spec_ref = SpecRef::new("3gpp", "TS29281", "5.1");
        if input.len() > ctx.max_message_len {
            return Err(
                DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 0).with_spec_ref(spec_ref)
            );
        }

        if input.len() < 8 {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec_ref));
        }

        let b1 = input[0];
        let version = (b1 >> 5) & 0x07;
        let protocol_type = ((b1 >> 4) & 0x01) != 0;
        let reserved = (b1 >> 3) & 0x01;
        let ext_hdr_flag = ((b1 >> 2) & 0x01) != 0;
        let seq_num_flag = ((b1 >> 1) & 0x01) != 0;
        let npdu_num_flag = (b1 & 0x01) != 0;

        if version != 1 {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidEnumValue {
                    field: "version",
                    value: version as u64,
                },
                0,
            )
            .with_spec_ref(spec_ref));
        }

        if !protocol_type {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidEnumValue {
                    field: "protocol_type",
                    value: 0,
                },
                0,
            )
            .with_spec_ref(spec_ref));
        }

        if validation_strictness(ctx.validation_level) >= 2 && reserved != 0 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "reserved bit must be zero",
                },
                0,
            )
            .with_spec_ref(spec_ref));
        }

        let message_type = input[1];
        let length = u16::from_be_bytes([input[2], input[3]]);
        let teid = u32::from_be_bytes([input[4], input[5], input[6], input[7]]);

        let total_declared_len = match 8usize.checked_add(length as usize) {
            Some(len) => len,
            None => {
                return Err(
                    DecodeError::new(DecodeErrorCode::LengthOverflow, 2).with_spec_ref(spec_ref)
                );
            }
        };

        if input.len() < total_declared_len {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, input.len()).with_spec_ref(spec_ref)
            );
        }

        let packet_bytes = &input[..total_declared_len];
        let tail_bytes = &input[total_declared_len..];

        let mut optional_fields_len: usize = 0;
        let mut sequence_number = None;
        let mut npdu_number = None;
        let mut next_ext_type = None;
        let mut raw_sequence_number = None;
        let mut raw_npdu_number = None;
        let mut raw_next_ext_type = None;

        if ext_hdr_flag || seq_num_flag || npdu_num_flag {
            optional_fields_len = 4;
            if (length as usize) < 4 {
                return Err(DecodeError::new(
                    DecodeErrorCode::InvalidLength {
                        reason: "length smaller than optional fields size (4 octets)",
                    },
                    8,
                )
                .with_spec_ref(spec_ref));
            }

            let seq = u16::from_be_bytes([packet_bytes[8], packet_bytes[9]]);
            raw_sequence_number = Some(seq);
            if seq_num_flag {
                sequence_number = Some(seq);
            }

            let npdu = packet_bytes[10];
            raw_npdu_number = Some(npdu);
            if npdu_num_flag {
                npdu_number = Some(npdu);
            }

            let next_ext = packet_bytes[11];
            raw_next_ext_type = Some(next_ext);
            next_ext_type = Some(next_ext);

            if validation_strictness(ctx.validation_level) >= 2 && ext_hdr_flag && next_ext == 0 {
                return Err(DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "extension header flag set but next extension header type is 0",
                    },
                    11,
                )
                .with_spec_ref(spec_ref));
            }
        }

        let mut ext_headers_len = 0usize;
        if ext_hdr_flag {
            let mut current_next_ext = next_ext_type.unwrap_or(0);
            let mut current_offset = 12usize;
            let mut depth = 0;
            let mut ie_count = 0;

            while current_next_ext != 0 {
                depth += 1;
                if depth > ctx.max_depth {
                    return Err(
                        DecodeError::new(DecodeErrorCode::DepthExceeded, current_offset)
                            .with_spec_ref(spec_ref),
                    );
                }

                ie_count += 1;
                if ie_count > ctx.max_ies {
                    return Err(
                        DecodeError::new(DecodeErrorCode::IeCountExceeded, current_offset)
                            .with_spec_ref(spec_ref),
                    );
                }

                let remaining_in_packet = match total_declared_len.checked_sub(current_offset) {
                    Some(len) => len,
                    None => {
                        return Err(DecodeError::new(
                            DecodeErrorCode::LengthOverflow,
                            current_offset,
                        )
                        .with_spec_ref(spec_ref));
                    }
                };

                if remaining_in_packet < 4 {
                    return Err(DecodeError::new(DecodeErrorCode::Truncated, current_offset)
                        .with_spec_ref(spec_ref));
                }

                let ext_len_units = packet_bytes[current_offset] as usize;
                if ext_len_units == 0 {
                    return Err(DecodeError::new(
                        DecodeErrorCode::InvalidLength {
                            reason: "extension header units is zero",
                        },
                        current_offset,
                    )
                    .with_spec_ref(spec_ref));
                }

                let ext_len_bytes = match ext_len_units.checked_mul(4) {
                    Some(len) => len,
                    None => {
                        return Err(DecodeError::new(
                            DecodeErrorCode::LengthOverflow,
                            current_offset,
                        )
                        .with_spec_ref(spec_ref));
                    }
                };

                if remaining_in_packet < ext_len_bytes {
                    return Err(DecodeError::new(DecodeErrorCode::Truncated, current_offset)
                        .with_spec_ref(spec_ref));
                }

                let next_ext_offset = match current_offset
                    .checked_add(ext_len_bytes)
                    .and_then(|offset| offset.checked_sub(1))
                {
                    Some(offset) => offset,
                    None => {
                        return Err(DecodeError::new(
                            DecodeErrorCode::LengthOverflow,
                            current_offset,
                        )
                        .with_spec_ref(spec_ref));
                    }
                };

                let next_ext = packet_bytes[next_ext_offset];

                // ProcedureAware semantic validation on known extension headers (PDU Session Container)
                if ctx.validation_level == ValidationLevel::ProcedureAware
                    && current_next_ext == 0x85
                {
                    let ext = GtpuExtensionHeader {
                        ext_type: current_next_ext,
                        content: &packet_bytes[current_offset + 1..next_ext_offset],
                        next_ext_type: next_ext,
                    };
                    if PduSessionContainer::decode(&ext).is_err() {
                        return Err(DecodeError::new(
                            DecodeErrorCode::Structural {
                                reason: "malformed PDU Session Container",
                            },
                            current_offset,
                        )
                        .with_spec_ref(spec_ref));
                    }
                }

                current_next_ext = next_ext;
                current_offset = match current_offset.checked_add(ext_len_bytes) {
                    Some(offset) => offset,
                    None => {
                        return Err(DecodeError::new(
                            DecodeErrorCode::LengthOverflow,
                            current_offset,
                        )
                        .with_spec_ref(spec_ref));
                    }
                };
            }

            ext_headers_len = match current_offset.checked_sub(12) {
                Some(len) => len,
                None => {
                    return Err(
                        DecodeError::new(DecodeErrorCode::LengthOverflow, current_offset)
                            .with_spec_ref(spec_ref),
                    );
                }
            };
        }

        let opt_and_ext_len = match optional_fields_len.checked_add(ext_headers_len) {
            Some(len) => len,
            None => {
                return Err(
                    DecodeError::new(DecodeErrorCode::LengthOverflow, 8).with_spec_ref(spec_ref)
                );
            }
        };

        if (length as usize) < opt_and_ext_len {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "length smaller than optional and extensions size",
                },
                2,
            )
            .with_spec_ref(spec_ref));
        }

        let payload_len = match (length as usize).checked_sub(opt_and_ext_len) {
            Some(len) => len,
            None => {
                return Err(
                    DecodeError::new(DecodeErrorCode::LengthOverflow, 8).with_spec_ref(spec_ref)
                );
            }
        };

        let raw_ext_start = 8 + optional_fields_len;
        let raw_ext_end = raw_ext_start + ext_headers_len;
        let raw_extension_headers = &packet_bytes[raw_ext_start..raw_ext_end];

        let payload_start = raw_ext_end;
        let payload_end = match payload_start.checked_add(payload_len) {
            Some(end) => end,
            None => {
                return Err(
                    DecodeError::new(DecodeErrorCode::LengthOverflow, payload_start)
                        .with_spec_ref(spec_ref),
                );
            }
        };

        if payload_end != total_declared_len {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "payload boundaries mismatch",
                },
                8,
            )
            .with_spec_ref(spec_ref));
        }

        let payload = &packet_bytes[payload_start..payload_end];

        let header = GtpuHeader {
            version,
            protocol_type,
            reserved,
            ext_hdr_flag,
            seq_num_flag,
            npdu_num_flag,
            message_type,
            length,
            teid,
            sequence_number,
            npdu_number,
            next_ext_type,
            raw_sequence_number,
            raw_npdu_number,
            raw_next_ext_type,
        };

        Ok((
            tail_bytes,
            GtpuMessage {
                header,
                raw_extension_headers,
                payload,
            },
        ))
    }
}

impl<'a> Encode for GtpuMessage<'a> {
    /// Calculate required buffer capacity.
    ///
    /// @spec 3GPP TS29281 R18 5.1
    /// @req REQ-3GPP-TS29281-R18-5.1-006
    /// @conformance full
    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        let spec_ref = SpecRef::new("3gpp", "TS29281", "5.1");
        let mut len = 8usize;

        let (has_ext, has_seq, has_npdu) = if ctx.raw_preserving {
            (
                self.header.ext_hdr_flag,
                self.header.seq_num_flag,
                self.header.npdu_num_flag,
            )
        } else {
            (
                !self.raw_extension_headers.is_empty()
                    || (self.header.next_ext_type.unwrap_or(0) != 0),
                self.header.sequence_number.is_some(),
                self.header.npdu_number.is_some(),
            )
        };

        if has_ext || has_seq || has_npdu {
            len = len
                .checked_add(4)
                .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref.clone()))?;
        }

        len = len
            .checked_add(self.raw_extension_headers.len())
            .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref.clone()))?;

        len = len
            .checked_add(self.payload.len())
            .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref))?;

        Ok(len)
    }

    /// Encode GtpuMessage in either Canonical or Raw-Preserving mode.
    ///
    /// @spec 3GPP TS29281 R18 5.1
    /// @req REQ-3GPP-TS29281-R18-5.1-007
    /// @conformance full
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let spec_ref = SpecRef::new("3gpp", "TS29281", "5.1");
        let len = self.wire_len(ctx)?;
        ctx.check_capacity(len)?;

        dst.reserve(len);

        let (has_ext, has_seq, has_npdu) = if ctx.raw_preserving {
            (
                self.header.ext_hdr_flag,
                self.header.seq_num_flag,
                self.header.npdu_num_flag,
            )
        } else {
            (
                !self.raw_extension_headers.is_empty()
                    || (self.header.next_ext_type.unwrap_or(0) != 0),
                self.header.sequence_number.is_some(),
                self.header.npdu_number.is_some(),
            )
        };

        let mut b1 = 0u8;
        if ctx.raw_preserving {
            let v = (self.header.version & 0x07) << 5;
            let pt = if self.header.protocol_type { 0x10 } else { 0 };
            let r = (self.header.reserved & 0x01) << 3;
            b1 |= v | pt | r;
        } else {
            // Canonical is always Version = 1 (0x20), PT = 1 (0x10)
            b1 |= 0x30;
        }

        if has_ext {
            b1 |= 0x04;
        }
        if has_seq {
            b1 |= 0x02;
        }
        if has_npdu {
            b1 |= 0x01;
        }

        dst.put_u8(b1);
        dst.put_u8(self.header.message_type);

        let length_field_val = len.checked_sub(8).ok_or_else(|| {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "wire length smaller than header",
            })
            .with_spec_ref(spec_ref.clone())
        })?;

        let length_u16 = u16::try_from(length_field_val)
            .map_err(|_| EncodeError::length_overflow().with_spec_ref(spec_ref.clone()))?;

        dst.put_u16(length_u16);
        dst.put_u32(self.header.teid);

        if has_ext || has_seq || has_npdu {
            let seq = if ctx.raw_preserving {
                self.header
                    .raw_sequence_number
                    .unwrap_or_else(|| self.header.sequence_number.unwrap_or(0))
            } else {
                self.header.sequence_number.unwrap_or(0)
            };
            dst.put_u16(seq);

            let npdu = if ctx.raw_preserving {
                self.header
                    .raw_npdu_number
                    .unwrap_or_else(|| self.header.npdu_number.unwrap_or(0))
            } else {
                self.header.npdu_number.unwrap_or(0)
            };
            dst.put_u8(npdu);

            let next_ext = if ctx.raw_preserving {
                self.header
                    .raw_next_ext_type
                    .unwrap_or_else(|| self.header.next_ext_type.unwrap_or(0))
            } else {
                self.header.next_ext_type.unwrap_or(0)
            };
            dst.put_u8(next_ext);
        }

        dst.put_slice(self.raw_extension_headers);
        dst.put_slice(self.payload);

        Ok(())
    }
}

impl<'a> ToOwnedPdu for GtpuMessage<'a> {
    type Owned = OwnedGtpuMessage;

    fn to_owned_pdu(&self) -> Self::Owned {
        OwnedGtpuMessage {
            header: self.header.clone(),
            raw_extension_headers: Bytes::copy_from_slice(self.raw_extension_headers),
            payload: Bytes::copy_from_slice(self.payload),
        }
    }
}

impl OwnedDecode for OwnedGtpuMessage {
    /// Decodes an owned GTP-U message using zero-allocation buffer slicing.
    ///
    /// @spec 3GPP TS29281 R18 5.1
    /// @req REQ-3GPP-TS29281-R18-5.1-008
    /// @conformance full
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (_, borrowed) = GtpuMessage::decode(&input, ctx)?;

        let base_ptr = input.as_ptr() as usize;

        let ext_start = borrowed.raw_extension_headers.as_ptr() as usize - base_ptr;
        let ext_len = borrowed.raw_extension_headers.len();
        let raw_extension_headers = input.slice(ext_start..ext_start + ext_len);

        let payload_start = borrowed.payload.as_ptr() as usize - base_ptr;
        let payload_len = borrowed.payload.len();
        let payload = input.slice(payload_start..payload_start + payload_len);

        Ok(Self {
            header: borrowed.header,
            raw_extension_headers,
            payload,
        })
    }
}

impl Encode for OwnedGtpuMessage {
    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        let borrowed = GtpuMessage {
            header: self.header.clone(),
            raw_extension_headers: &self.raw_extension_headers,
            payload: &self.payload,
        };
        borrowed.wire_len(ctx)
    }

    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let borrowed = GtpuMessage {
            header: self.header.clone(),
            raw_extension_headers: &self.raw_extension_headers,
            payload: &self.payload,
        };
        borrowed.encode(dst, ctx)
    }
}
