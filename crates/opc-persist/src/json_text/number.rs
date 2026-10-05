//! Preserve the default JSON number conversion used by audit classification.
//!
//! Syntax has already passed Serde's public IgnoredAny decoder. Keep integers
//! exact through u64/i64; for other tokens retain a u64 significand and decimal
//! exponent, dropping digits only when the significand overflows. This pins the
//! pre-existing non-roundtrip conversion, including negative zero and underflow,
//! without calling dependency internals or opting into dependency features.

use super::Json;

pub(super) fn parse(input: &str) -> Result<Json, ()> {
    let (positive, input) = match input.strip_prefix('-') {
        Some(input) => (false, input),
        None => (true, input),
    };
    let integer_end = input.find(['.', 'e', 'E']).unwrap_or(input.len());
    let mut significand = 0_u64;
    let mut taken = 0;
    for digit in input[..integer_end].bytes() {
        let Some(next) = significand
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(digit - b'0')))
        else {
            break;
        };
        significand = next;
        taken += 1;
    }
    let mut exponent = i32::try_from(integer_end - taken).map_err(|_| ())?;
    let mut rest = &input[integer_end..];
    if rest.is_empty() && taken == integer_end {
        return Ok(if positive {
            Json::Unsigned(significand)
        } else if significand == 0 {
            Json::Float(-0.0)
        } else if significand <= 1_u64 << 63 {
            Json::Signed((significand as i64).wrapping_neg())
        } else {
            Json::Float(-(significand as f64))
        });
    }
    if let Some(fraction) = rest.strip_prefix('.') {
        let end = fraction.find(['e', 'E']).unwrap_or(fraction.len());
        for digit in fraction[..end].bytes() {
            let Some(next) = significand
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(digit - b'0')))
            else {
                break;
            };
            significand = next;
            exponent = exponent.checked_sub(1).ok_or(())?;
        }
        rest = &fraction[end..];
    }
    if !rest.is_empty() {
        let explicit = &rest[1..];
        let (negative, digits) = if let Some(digits) = explicit.strip_prefix('-') {
            (true, digits)
        } else {
            (false, explicit.strip_prefix('+').unwrap_or(explicit))
        };
        let mut magnitude = 0_i32;
        for digit in digits.bytes() {
            let Some(next) = magnitude
                .checked_mul(10)
                .and_then(|v| v.checked_add(i32::from(digit - b'0')))
            else {
                return if !negative && significand != 0 {
                    Err(())
                } else {
                    Ok(Json::Float(if positive { 0.0 } else { -0.0 }))
                };
            };
            magnitude = next;
        }
        exponent = if negative {
            exponent.saturating_sub(magnitude)
        } else {
            exponent.saturating_add(magnitude)
        };
    }
    let mut value = significand as f64;
    while exponent < -308 && value != 0.0 {
        value /= 1e308;
        exponent = exponent.saturating_add(308);
    }
    if value != 0.0 {
        if exponent > 308 {
            return Err(());
        }
        // Parse a short power-of-ten literal, giving the same correctly rounded
        // constant as a table of 1e0..1e308. powi can round differently.
        let power: f64 = format!("1e{}", exponent.unsigned_abs())
            .parse()
            .map_err(|_| ())?;
        if exponent >= 0 {
            value *= power;
        } else {
            value /= power;
        }
        if !value.is_finite() {
            return Err(());
        }
    }
    Ok(Json::Float(if positive { value } else { -value }))
}
