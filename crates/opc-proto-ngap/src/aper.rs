//! Bounded aligned open-type framing; nested ASN.1 remains generated.

use std::borrow::Cow;

use opc_protocol::{DecodeError, DecodeErrorCode};

fn error() -> DecodeError {
    DecodeError::new(
        DecodeErrorCode::Structural {
            reason: "ngap open type",
        },
        0,
    )
}

fn determinant(input: &[u8]) -> Result<(usize, bool, usize), DecodeError> {
    let first = *input.first().ok_or_else(error)?;
    match first {
        0..=127 => Ok((usize::from(first), false, 1)),
        128..=191 => {
            let second = *input.get(1).ok_or_else(error)?;
            Ok((
                usize::from(u16::from_be_bytes([first & 0x3f, second])),
                false,
                2,
            ))
        }
        193..=196 => Ok((usize::from(first & 0x3f) * 16384, true, 1)),
        _ => Err(error()),
    }
}

fn fragment(input: &[u8]) -> Result<(&[u8], &[u8], bool), DecodeError> {
    let (length, more, prefix) = determinant(input)?;
    let end = prefix.checked_add(length).ok_or_else(error)?;
    let value = input.get(prefix..end).ok_or_else(error)?;
    Ok((&input[end..], value, more))
}

/// Scan the complete physical framing before allocating a fragmented value.
/// The caller has already bounded the containing message. Borrow small values;
/// coalesce only actual fragment payload, never an advertised absent length.
pub(super) fn open_type(input: &[u8]) -> Result<(&[u8], Cow<'_, [u8]>), DecodeError> {
    let (remainder, value, more) = fragment(input)?;
    if !more {
        return Ok((remainder, Cow::Borrowed(value)));
    }
    let mut scan = remainder;
    let mut total = value.len();
    loop {
        let (next, part, more) = fragment(scan)?;
        total = total.checked_add(part.len()).ok_or_else(error)?;
        scan = next;
        if !more {
            break;
        }
    }
    let final_remainder = scan;
    let mut joined = Vec::with_capacity(total);
    let mut scan = input;
    loop {
        let (next, part, more) = fragment(scan)?;
        joined.extend_from_slice(part);
        scan = next;
        if !more {
            break;
        }
    }
    Ok((final_remainder, Cow::Owned(joined)))
}

pub(super) struct FramedIe<'a> {
    pub(super) remainder: &'a [u8],
    pub(super) header: [u8; 4],
    pub(super) value: Cow<'a, [u8]>,
}

/// Check an entire IE without materializing its open type. New typed transfer
/// admission uses this to preflight every physical IE before allocating its
/// container, and to skip opaque unknown values after policy selection.
pub(super) fn scan_ie(input: &[u8]) -> Result<(&[u8], [u8; 3]), DecodeError> {
    let prefix = input.get(..3).ok_or_else(error)?;
    let (remaining, _) = scan_open_type(&input[3..])?;
    Ok((remaining, [prefix[0], prefix[1], prefix[2]]))
}

/// Complete canonical fragment framing and payload size, without allocation.
pub(super) fn scan_open_type(input: &[u8]) -> Result<(&[u8], usize), DecodeError> {
    let mut remaining = input;
    let mut length = 0usize;
    loop {
        if matches!(remaining, [0x80, second, ..] if *second < 128) {
            return Err(error());
        }
        let (next, part, more) = fragment(remaining)?;
        length = length.checked_add(part.len()).ok_or_else(error)?;
        remaining = next;
        if !more {
            return Ok((remaining, length));
        }
    }
}

pub(super) fn ie(input: &[u8]) -> Result<FramedIe<'_>, DecodeError> {
    let prefix = input.get(..3).ok_or_else(error)?;
    let (remaining, value) = open_type(&input[3..])?;
    // Decode this fixed header with the selected generated IE type; replace
    // its empty Any value with the completely framed value afterwards.
    Ok(FramedIe {
        remainder: remaining,
        header: [prefix[0], prefix[1], prefix[2], 0],
        value,
    })
}
