//! BCD digit unpacking for NAS-5GS mobile identities and PLMNs (TS 24.501).
//!
//! 3GPP packs decimal digits into octets with the low-order nibble first and
//! the high-order nibble second. Unused nibbles are filled with `0xF`.

use std::fmt;

/// Errors that can occur while unpacking BCD data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BcdError {
    /// The input has fewer octets than required for the target type.
    TooShort {
        /// Minimum octets expected.
        expected: usize,
        /// Actual octets received.
        got: usize,
    },
    /// A nibble outside the digit range `0..=9` (and not the filler `0xF`)
    /// was encountered where a digit was required.
    InvalidDigit {
        /// Offset of the offending octet.
        octet: usize,
        /// Nibble index within the octet (0 = low, 1 = high).
        nibble: u8,
        /// Raw nibble value.
        value: u8,
    },
    /// The odd/even indicator and the actual nibble count disagree for an
    /// IMEI/IMEISV identity.
    InconsistentOddIndicator {
        /// Indicator from the type octet.
        odd: bool,
        /// Number of BCD nibbles decoded (excluding the type nibble).
        nibble_count: usize,
    },
}

impl fmt::Display for BcdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { expected, got } => {
                write!(
                    f,
                    "BCD input too short: expected {expected} octets, got {got}"
                )
            }
            Self::InvalidDigit {
                octet,
                nibble,
                value,
            } => write!(
                f,
                "invalid BCD nibble at octet {octet} nibble {nibble}: 0x{value:X}"
            ),
            Self::InconsistentOddIndicator { odd, nibble_count } => write!(
                f,
                "IMEI odd/even indicator {odd} inconsistent with {nibble_count} decoded nibbles"
            ),
        }
    }
}

impl std::error::Error for BcdError {}

/// Unpacked PLMN digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plmn {
    /// Mobile Country Code (three digits).
    pub mcc: String,
    /// Mobile Network Code (two or three digits).
    pub mnc: String,
}

impl Plmn {
    /// Total number of digits in the PLMN (5 or 6).
    pub fn digit_count(&self) -> usize {
        self.mcc.len() + self.mnc.len()
    }
}

/// Unpack all nibbles of `buf` in low-then-high order, stopping before the
/// first `0xF` filler nibble.
pub fn unpack_bcd_digits(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len() * 2);
    for &octet in buf {
        let low = octet & 0x0F;
        if low == 0x0F {
            break;
        }
        out.push(low);
        let high = (octet >> 4) & 0x0F;
        if high == 0x0F {
            break;
        }
        out.push(high);
    }
    out
}

/// Unpack the three BCD octets of a PLMN into MCC and MNC.
///
/// TS 24.008/24.501 PLMN packing:
/// - octet 1 low = MCC digit 1, high = MCC digit 2
/// - octet 2 low = MCC digit 3, high = MNC digit 3 (0xF if 2-digit MNC)
/// - octet 3 low = MNC digit 1, high = MNC digit 2
pub fn unpack_plmn(octets: [u8; 3]) -> Result<Plmn, BcdError> {
    let digits: Vec<u8> = octets
        .iter()
        .flat_map(|&o| [o & 0x0F, (o >> 4) & 0x0F])
        .collect();

    // MCC digits must be valid decimal digits.
    for (i, &d) in digits[..3].iter().enumerate() {
        if d > 9 {
            return Err(BcdError::InvalidDigit {
                octet: i / 2,
                nibble: (i % 2) as u8,
                value: d,
            });
        }
    }
    // MNC digits 1 and 2 must be valid decimal digits.
    for (i, &d) in digits[4..6].iter().enumerate() {
        if d > 9 {
            return Err(BcdError::InvalidDigit {
                octet: (4 + i) / 2,
                nibble: ((4 + i) % 2) as u8,
                value: d,
            });
        }
    }

    let mcc = format!("{}{}{}", digits[0], digits[1], digits[2]);
    let mnc = if digits[3] == 0x0F {
        format!("{}{}", digits[4], digits[5])
    } else {
        if digits[3] > 9 {
            return Err(BcdError::InvalidDigit {
                octet: 1,
                nibble: 1,
                value: digits[3],
            });
        }
        format!("{}{}{}", digits[4], digits[5], digits[3])
    };
    Ok(Plmn { mcc, mnc })
}

/// Unpack a two-octet routing indicator, returning the decimal string.
///
/// Digits are packed low-nibble-first; a `0xF` nibble marks the end.
pub fn unpack_routing_indicator(octets: [u8; 2]) -> Result<String, BcdError> {
    let digits = unpack_bcd_digits(&octets);
    for (i, &d) in digits.iter().enumerate() {
        if d > 9 {
            return Err(BcdError::InvalidDigit {
                octet: i / 2,
                nibble: (i % 2) as u8,
                value: d,
            });
        }
    }
    Ok(digits.iter().map(|d| char::from(b'0' + d)).collect())
}

/// Unpack an IMEI or IMEISV identity content (including the type octet).
///
/// `content` is the full mobile-identity content bytes. The first octet
/// contains the identity type in bits 1-3, the odd/even indicator in bit 4,
/// and the first decimal digit in bits 5-8. Subsequent octets carry BCD
/// digit pairs low-nibble-first.
///
/// The odd indicator means the number of digits is odd; the last high
/// nibble is a filler `0xF`.
pub fn unpack_imei(content: &[u8]) -> Result<String, BcdError> {
    if content.is_empty() {
        return Err(BcdError::TooShort {
            expected: 1,
            got: 0,
        });
    }
    let first_octet = content[0];
    let odd = (first_octet & 0x08) != 0;
    let first_digit = (first_octet >> 4) & 0x0F;
    if first_digit > 9 {
        return Err(BcdError::InvalidDigit {
            octet: 0,
            nibble: 1,
            value: first_digit,
        });
    }

    let mut digits = Vec::with_capacity(16);
    digits.push(first_digit);

    for (octet_idx, &octet) in content.iter().enumerate().skip(1) {
        let low = octet & 0x0F;
        if low == 0x0F {
            break;
        }
        if low > 9 {
            return Err(BcdError::InvalidDigit {
                octet: octet_idx,
                nibble: 0,
                value: low,
            });
        }
        digits.push(low);
        let high = (octet >> 4) & 0x0F;
        if high == 0x0F {
            break;
        }
        if high > 9 {
            return Err(BcdError::InvalidDigit {
                octet: octet_idx,
                nibble: 1,
                value: high,
            });
        }
        digits.push(high);
    }

    let expected_parity_odd = odd;
    let actual_odd = (digits.len() % 2) == 1;
    if expected_parity_odd != actual_odd {
        return Err(BcdError::InconsistentOddIndicator {
            odd,
            nibble_count: digits.len(),
        });
    }

    Ok(digits.iter().map(|d| char::from(b'0' + d)).collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn plmn_two_digit_mnc() {
        // MCC=208, MNC=93 -> 0x02 0xF8 0x39
        let plmn = unpack_plmn([0x02, 0xF8, 0x39]).unwrap();
        assert_eq!(plmn.mcc, "208");
        assert_eq!(plmn.mnc, "93");
        assert_eq!(plmn.digit_count(), 5);
    }

    #[test]
    fn plmn_three_digit_mnc() {
        // MCC=123, MNC=456 -> 0x21 0x63 0x54
        let plmn = unpack_plmn([0x21, 0x63, 0x54]).unwrap();
        assert_eq!(plmn.mcc, "123");
        assert_eq!(plmn.mnc, "456");
        assert_eq!(plmn.digit_count(), 6);
    }

    #[test]
    fn plmn_invalid_digit_rejected() {
        // Replace a digit nibble with 0xA.
        assert!(unpack_plmn([0x0A, 0xF8, 0x39]).is_err());
    }

    #[test]
    fn routing_indicator_with_filler() {
        // "12" encoded as 0x21 0xFF
        assert_eq!(unpack_routing_indicator([0x21, 0xFF]).unwrap(), "12");
    }

    #[test]
    fn routing_indicator_odd_length() {
        // "123" encoded as 0x21 0xF3
        assert_eq!(unpack_routing_indicator([0x21, 0xF3]).unwrap(), "123");
    }

    #[test]
    fn routing_indicator_full() {
        // "1234" encoded as 0x21 0x43
        assert_eq!(unpack_routing_indicator([0x21, 0x43]).unwrap(), "1234");
    }

    #[test]
    fn imei_odd_length() {
        // IMEI = 356412111238480 (15 digits).
        // Type=3, odd=1, first digit=3 -> first octet 0x3B.
        // Remaining 14 digits fit in 7 octets:
        // (5,6)->0x65, (4,1)->0x14, (2,1)->0x12, (1,1)->0x11,
        // (2,3)->0x32, (8,4)->0x48, (8,0)->0x08.
        let content = &[0x3B, 0x65, 0x14, 0x12, 0x11, 0x32, 0x48, 0x08];
        assert_eq!(unpack_imei(content).unwrap(), "356412111238480");
    }

    #[test]
    fn imeisv_even_length() {
        // IMEISV = 1234567890123456 (16 digits), type=5, even.
        // First octet = (1<<4) | 5 = 0x15.
        // Remaining 15 digits need 8 octets with last high nibble F.
        let content = &[0x15, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54, 0xF6];
        assert_eq!(unpack_imei(content).unwrap(), "1234567890123456");
    }

    #[test]
    fn imei_rejects_bad_parity() {
        // Same as the IMEI test but clear the odd indicator: would imply an
        // even digit count, but the content has 15 digits.
        let content = &[0x33, 0x65, 0x14, 0x12, 0x11, 0x32, 0x48, 0x08];
        assert!(unpack_imei(content).is_err());
    }
}
