//! Bounded aligned open-type framing; nested ASN.1 remains generated.

use opc_protocol::{DecodeError, DecodeErrorCode};
use zeroize::Zeroizing;

use crate::sensitive::{SensitiveBytes, SensitiveValue};

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
pub(super) fn open_type(input: &[u8]) -> Result<(&[u8], SensitiveValue<'_>), DecodeError> {
    let (remainder, value, more) = fragment(input)?;
    if !more {
        return Ok((remainder, SensitiveValue::Borrowed(value)));
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
    let mut joined = Zeroizing::new(Vec::with_capacity(total));
    let mut scan = input;
    loop {
        let (next, part, more) = fragment(scan)?;
        joined.extend_from_slice(part);
        scan = next;
        if !more {
            break;
        }
    }
    Ok((
        final_remainder,
        SensitiveValue::Owned(SensitiveBytes::from_zeroizing(joined)),
    ))
}

pub(super) struct FramedIe<'a> {
    pub(super) remainder: &'a [u8],
    pub(super) header: [u8; 4],
    pub(super) value: SensitiveValue<'a>,
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
    // Keep the fixed header separate from the wiping open-type owner.
    Ok(FramedIe {
        remainder: remaining,
        header: [prefix[0], prefix[1], prefix[2], 0],
        value,
    })
}

fn bitmap_presence(
    input: &[u8],
    start_bit: usize,
    count: usize,
) -> Result<(&[u8], usize), DecodeError> {
    let end_bit = start_bit.checked_add(count).ok_or_else(error)?;
    let end_byte = end_bit.div_ceil(8);
    let bitmap = input.get(..end_byte).ok_or_else(error)?;
    if end_bit % 8 != 0 && bitmap[end_byte - 1] & ((1 << (8 - end_bit % 8)) - 1) != 0 {
        return Err(error());
    }
    let present = (start_bit..end_bit)
        .filter(|&bit| bitmap[bit / 8] & (0x80 >> (bit % 8)) != 0)
        .count();
    Ok((&input[end_byte..], present))
}

/// X.691 11.9.3.4, 11.9.3.8 and 19.7–19.9: scan the complete presence bitmap
/// before skipping opaque SEQUENCE additions. The caller bounds the input;
/// their full encoding remains in the zeroizing raw PDU without extra copies.
pub(super) fn sequence_extensions(input: &[u8]) -> Result<(), DecodeError> {
    let first = *input.first().ok_or_else(error)?;
    let (mut remaining, present) = if first & 0x80 == 0 {
        bitmap_presence(input, 7, usize::from(first >> 1) + 1)?
    } else {
        // Large normally-small lengths use aligned unconstrained determinants,
        // measured in bits. Each fragment precedes the next determinant; an
        // exact 16K multiple still requires the final zero-length determinant.
        if first & 0x7f != 0 {
            return Err(error());
        }
        let mut remaining = &input[1..];
        let mut count = 0usize;
        let mut present = 0usize;
        loop {
            if matches!(remaining, [0x80, second, ..] if *second < 128) {
                return Err(error());
            }
            let (length, more, prefix) = determinant(remaining)?;
            let (next, part_present) = bitmap_presence(&remaining[prefix..], 0, length)?;
            count = count.checked_add(length).ok_or_else(error)?;
            present = present.checked_add(part_present).ok_or_else(error)?;
            remaining = next;
            if !more {
                break;
            }
        }
        if count <= 64 {
            return Err(error());
        }
        (remaining, present)
    };
    for _ in 0..present {
        remaining = scan_open_type(remaining)?.0;
    }
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(error())
    }
}
