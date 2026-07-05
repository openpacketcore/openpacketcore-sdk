//! GTP-U message helpers used by the dataplane testkit.

use bytes::{Bytes, BytesMut};
use opc_proto_gtpu::{GtpuHeader, GtpuMessage, OwnedGtpuMessage};
use opc_protocol::{
    BorrowDecode, DecodeContext, Encode, EncodeContext, OwnedDecode, UnknownIePolicy,
    ValidationLevel,
};

use crate::DataplaneTestkitError;

/// Standard GTP-U UDP port.
pub const GTPU_UDP_PORT: u16 = 2152;

/// GTP-U Echo Request message type.
pub const GTPU_MSG_ECHO_REQUEST: u8 = 1;
/// GTP-U Echo Response message type.
pub const GTPU_MSG_ECHO_RESPONSE: u8 = 2;
/// GTP-U Error Indication message type.
pub const GTPU_MSG_ERROR_INDICATION: u8 = 26;
/// GTP-U Supported Extension Headers Notification message type.
pub const GTPU_MSG_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION: u8 = 31;
/// GTP-U End Marker message type.
pub const GTPU_MSG_END_MARKER: u8 = 254;
/// GTP-U G-PDU message type.
pub const GTPU_MSG_GPDU: u8 = 255;

/// Decode a GTP-U datagram into an owned message.
pub fn decode_gtpu(input: &[u8]) -> Result<OwnedGtpuMessage, DataplaneTestkitError> {
    let ctx = DecodeContext {
        validation_level: ValidationLevel::Structural,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::default()
    };
    let (tail, _borrowed) = GtpuMessage::decode(input, ctx)
        .map_err(|err| DataplaneTestkitError::GtpuDecode(err.to_string()))?;
    if !tail.is_empty() {
        return Err(DataplaneTestkitError::invalid_packet(
            "GTP-U datagram contains trailing bytes",
        ));
    }
    OwnedGtpuMessage::decode_owned(Bytes::copy_from_slice(input), ctx)
        .map_err(|err| DataplaneTestkitError::GtpuDecode(err.to_string()))
}

/// Encode a plain G-PDU carrying one T-PDU.
pub fn encode_gpdu(teid: u32, tpdu: &[u8]) -> Result<Vec<u8>, DataplaneTestkitError> {
    encode_message(GTPU_MSG_GPDU, teid, None, None, &[], tpdu)
}

/// Encode a G-PDU with an optional extension-header chain.
pub fn encode_gpdu_with_extensions(
    teid: u32,
    first_extension_type: u8,
    raw_extension_headers: &[u8],
    tpdu: &[u8],
) -> Result<Vec<u8>, DataplaneTestkitError> {
    encode_message(
        GTPU_MSG_GPDU,
        teid,
        None,
        Some(first_extension_type),
        raw_extension_headers,
        tpdu,
    )
}

/// Encode a GTP-U Echo Request with TEID zero and a sequence number.
pub fn encode_echo_request(sequence_number: u16) -> Result<Vec<u8>, DataplaneTestkitError> {
    encode_message(
        GTPU_MSG_ECHO_REQUEST,
        0,
        Some(sequence_number),
        None,
        &[],
        &[],
    )
}

pub(crate) fn encode_echo_response(
    sequence_number: u16,
    recovery_counter: u8,
) -> Result<Vec<u8>, DataplaneTestkitError> {
    encode_message(
        GTPU_MSG_ECHO_RESPONSE,
        0,
        Some(sequence_number),
        None,
        &[],
        &[14, recovery_counter],
    )
}

pub(crate) fn encode_error_indication(
    sequence_number: u16,
    payload: &[u8],
) -> Result<Vec<u8>, DataplaneTestkitError> {
    encode_message(
        GTPU_MSG_ERROR_INDICATION,
        0,
        Some(sequence_number),
        None,
        &[],
        payload,
    )
}

/// Validate that an Error Indication payload carries the required IEs.
pub fn validate_error_indication_ies(payload: &[u8]) -> Result<(), DataplaneTestkitError> {
    let mut offset = 0usize;
    let mut has_teid_data = false;
    let mut has_peer_address = false;

    while offset < payload.len() {
        let ie_type = payload[offset];
        offset = offset
            .checked_add(1)
            .ok_or(DataplaneTestkitError::Overflow { field: "ie_offset" })?;

        match ie_type {
            16 => {
                let end = offset
                    .checked_add(4)
                    .ok_or(DataplaneTestkitError::Overflow { field: "ie_offset" })?;
                if end > payload.len() {
                    return Err(DataplaneTestkitError::truncated("TEID Data I IE"));
                }
                has_teid_data = true;
                offset = end;
            }
            133 => {
                let len_end = offset
                    .checked_add(2)
                    .ok_or(DataplaneTestkitError::Overflow { field: "ie_offset" })?;
                if len_end > payload.len() {
                    return Err(DataplaneTestkitError::truncated("GTP-U Peer Address IE"));
                }
                let len = usize::from(u16::from_be_bytes([payload[offset], payload[offset + 1]]));
                offset = len_end;
                if len != 4 && len != 16 {
                    return Err(DataplaneTestkitError::invalid_packet(
                        "GTP-U Peer Address IE length must be IPv4 or IPv6",
                    ));
                }
                let value_end = offset
                    .checked_add(len)
                    .ok_or(DataplaneTestkitError::Overflow { field: "ie_offset" })?;
                if value_end > payload.len() {
                    return Err(DataplaneTestkitError::truncated("GTP-U Peer Address IE"));
                }
                has_peer_address = true;
                offset = value_end;
            }
            128..=u8::MAX => {
                let len_end = offset
                    .checked_add(2)
                    .ok_or(DataplaneTestkitError::Overflow { field: "ie_offset" })?;
                if len_end > payload.len() {
                    return Err(DataplaneTestkitError::truncated("GTP-U TLV IE"));
                }
                let len = usize::from(u16::from_be_bytes([payload[offset], payload[offset + 1]]));
                offset = len_end;
                offset = offset
                    .checked_add(len)
                    .ok_or(DataplaneTestkitError::Overflow { field: "ie_offset" })?;
                if offset > payload.len() {
                    return Err(DataplaneTestkitError::truncated("GTP-U TLV IE"));
                }
            }
            _ => {
                return Err(DataplaneTestkitError::invalid_packet(
                    "unsupported fixed-length GTP-U IE",
                ));
            }
        }
    }

    if !has_teid_data {
        return Err(DataplaneTestkitError::invalid_packet(
            "Error Indication missing TEID Data I IE",
        ));
    }
    if !has_peer_address {
        return Err(DataplaneTestkitError::invalid_packet(
            "Error Indication missing GTP-U Peer Address IE",
        ));
    }
    Ok(())
}

fn encode_message(
    message_type: u8,
    teid: u32,
    sequence_number: Option<u16>,
    first_extension_type: Option<u8>,
    raw_extension_headers: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, DataplaneTestkitError> {
    let has_ext = first_extension_type.is_some() || !raw_extension_headers.is_empty();
    let header = GtpuHeader {
        version: 1,
        protocol_type: true,
        reserved: 0,
        ext_hdr_flag: has_ext,
        seq_num_flag: sequence_number.is_some(),
        npdu_num_flag: false,
        message_type,
        length: 0,
        teid,
        sequence_number,
        npdu_number: None,
        next_ext_type: first_extension_type,
        raw_sequence_number: sequence_number,
        raw_npdu_number: Some(0),
        raw_next_ext_type: first_extension_type,
    };
    let message = GtpuMessage {
        header,
        raw_extension_headers,
        payload,
    };
    let mut bytes = BytesMut::new();
    message
        .encode(&mut bytes, EncodeContext::default())
        .map_err(|err| DataplaneTestkitError::GtpuEncode(err.to_string()))?;
    Ok(bytes.to_vec())
}
