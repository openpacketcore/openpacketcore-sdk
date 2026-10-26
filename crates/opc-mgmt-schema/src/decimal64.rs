//! Exact RFC 7950 section 9.3 values and RFC 7951 string encoding.

use std::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

/// A decimal value with its validated YANG fraction-digits (1 through 18).
#[derive(Debug, Clone, Copy)]
pub struct Decimal64 {
    scaled: i64,
    fraction_digits: u8,
}

/// Invalid decimal syntax, scale, precision or signed 64-bit coefficient.
/// The error deliberately carries no input value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimal64Error;

impl fmt::Display for Decimal64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid YANG decimal64 value or fraction-digits")
    }
}
impl std::error::Error for Decimal64Error {}

impl Decimal64 {
    /// Creates a value whose magnitude is `scaled * 10^-fraction_digits`.
    pub const fn from_scaled(scaled: i64, fraction_digits: u8) -> Result<Self, Decimal64Error> {
        if fraction_digits < 1 || fraction_digits > 18 {
            return Err(Decimal64Error);
        }
        Ok(Self {
            scaled,
            fraction_digits,
        })
    }

    /// Parses the YANG lexical form without rounding or accepting exponents.
    pub fn parse(text: &str, fraction_digits: u8) -> Result<Self, Decimal64Error> {
        Self::from_scaled(0, fraction_digits)?;
        let negative = text.starts_with('-');
        let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
        let (whole, fraction) = match digits.split_once('.') {
            Some((whole, fraction)) if !fraction.is_empty() => (whole, fraction),
            Some(_) => return Err(Decimal64Error),
            None => (digits, ""),
        };
        if whole.is_empty()
            || !whole.bytes().all(|b| b.is_ascii_digit())
            || !fraction.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Decimal64Error);
        }
        // Trailing zeros do not change the value space defined by fraction-digits.
        let fraction = fraction.trim_end_matches('0');
        if fraction.len() > usize::from(fraction_digits) {
            return Err(Decimal64Error);
        }
        let parse = |digits: &str| {
            let digits = digits.trim_start_matches('0');
            if digits.is_empty() {
                Ok(0_u64)
            } else {
                digits.parse::<u64>().map_err(|_| Decimal64Error)
            }
        };
        let whole = parse(whole)?;
        let fractional =
            parse(fraction)? * 10_u64.pow(u32::from(fraction_digits) - fraction.len() as u32);
        let magnitude = whole
            .checked_mul(10_u64.pow(u32::from(fraction_digits)))
            .and_then(|whole| whole.checked_add(fractional))
            .ok_or(Decimal64Error)?;
        let signed = if negative {
            -i128::from(magnitude)
        } else {
            i128::from(magnitude)
        };
        let scaled = i64::try_from(signed).map_err(|_| Decimal64Error)?;
        Ok(Self {
            scaled,
            fraction_digits,
        })
    }

    /// Returns the exact signed coefficient.
    pub const fn scaled(self) -> i64 {
        self.scaled
    }
    /// Returns the schema's declared fraction-digits.
    pub const fn fraction_digits(self) -> u8 {
        self.fraction_digits
    }

    fn normalized(self) -> i128 {
        i128::from(self.scaled) * 10_i128.pow(u32::from(18 - self.fraction_digits))
    }
}

impl PartialEq for Decimal64 {
    fn eq(&self, other: &Self) -> bool {
        self.normalized() == other.normalized()
    }
}
impl Eq for Decimal64 {}
impl PartialOrd for Decimal64 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Decimal64 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.normalized().cmp(&other.normalized())
    }
}
impl Hash for Decimal64 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.normalized().hash(state);
    }
}

impl fmt::Display for Decimal64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let factor = 10_u64.pow(u32::from(self.fraction_digits));
        let magnitude = self.scaled.unsigned_abs();
        let mut fraction = magnitude % factor;
        let mut width = usize::from(self.fraction_digits);
        while width > 1 && fraction.is_multiple_of(10) {
            fraction /= 10;
            width -= 1;
        }
        if self.scaled < 0 {
            f.write_str("-")?;
        }
        write!(f, "{}.{fraction:0width$}", magnitude / factor)
    }
}

/// A generated leaf's decimal64 type, with scale fixed by its YANG schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FixedDecimal64<const FRACTION_DIGITS: u8>(i64);

impl<const F: u8> FixedDecimal64<F> {
    /// Creates an exact value from a coefficient; the scale must be 1..=18.
    pub const fn from_scaled(scaled: i64) -> Self {
        const {
            assert!(F >= 1 && F <= 18, "YANG fraction-digits must be 1..=18");
        }
        Self(scaled)
    }
    /// Returns the exact signed coefficient.
    pub const fn scaled(self) -> i64 {
        self.0
    }
    /// Erases the compile-time scale while preserving the exact value.
    pub const fn as_decimal(self) -> Decimal64 {
        Decimal64 {
            scaled: self.0,
            fraction_digits: F,
        }
    }
    /// Converts only for XPath's IEEE 754 number semantics (RFC 7950 §6.4).
    pub fn as_xpath_number(self) -> f64 {
        self.to_string()
            .parse()
            .expect("validated decimal64 has a finite XPath number")
    }
}
impl<const F: u8> Default for FixedDecimal64<F> {
    fn default() -> Self {
        Self::from_scaled(0)
    }
}
impl<const F: u8> FromStr for FixedDecimal64<F> {
    type Err = Decimal64Error;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Decimal64::parse(text, F).map(|value| Self(value.scaled))
    }
}
impl<const F: u8> fmt::Display for FixedDecimal64<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_decimal().fmt(f)
    }
}
impl<const F: u8> serde::Serialize for FixedDecimal64<F> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de, const F: u8> serde::Deserialize<'de> for FixedDecimal64<F> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <String as serde::Deserialize>::deserialize(deserializer)
            .map_err(|_| serde::de::Error::custom(Decimal64Error))?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scale_roundtrips_signed_bounds_and_adjacent_coefficients() {
        for scale in 1..=18 {
            for coefficient in [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX] {
                let value = Decimal64::from_scaled(coefficient, scale).unwrap();
                let text = value.to_string();
                assert_eq!(
                    Decimal64::parse(&text, scale).unwrap().scaled(),
                    coefficient
                );
                assert!(text.contains('.'));
            }
        }
        assert_eq!(
            Decimal64::from_scaled(i64::MIN, 18).unwrap().to_string(),
            "-9.223372036854775808"
        );
        assert_eq!(
            Decimal64::from_scaled(i64::MAX, 2).unwrap().to_string(),
            "92233720368547758.07"
        );
    }

    #[test]
    fn lexical_forms_are_exact_and_errors_do_not_echo_values() {
        for (text, expected) in [
            ("+001.230000", "1.23"),
            ("-0", "0.0"),
            ("1", "1.0"),
            ("0.01", "0.01"),
        ] {
            assert_eq!(Decimal64::parse(text, 2).unwrap().to_string(), expected);
        }
        for text in [
            "1.234",
            "1e2",
            "NaN",
            "inf",
            "1.",
            ".1",
            " 1",
            "1 ",
            "--1",
            "+-1",
            "１",
            "",
            "92233720368547758.08",
            "-92233720368547758.09",
            "184467440737095516160",
        ] {
            assert_eq!(Decimal64::parse(text, 2), Err(Decimal64Error));
        }
        for scale in [0, 19, 255] {
            assert!(Decimal64::parse("0", scale).is_err());
        }
        assert!("0".parse::<FixedDecimal64<0>>().is_err());
        assert!(Decimal64::parse("secret-value-marker", 2)
            .unwrap_err()
            .to_string()
            .find("secret-value-marker")
            .is_none());
    }

    #[test]
    fn equality_order_and_hash_are_numeric_across_scales() {
        use std::collections::HashSet;
        let a = Decimal64::parse("1.2", 1).unwrap();
        let b = Decimal64::parse("1.20", 18).unwrap();
        assert_eq!(a, b);
        assert_eq!(HashSet::from([a, b]).len(), 1);
        assert!(Decimal64::parse("1.21", 2).unwrap() > b);
        assert_ne!(
            Decimal64::parse("900719925474099.21", 2).unwrap(),
            Decimal64::parse("900719925474099.22", 2).unwrap()
        );
    }
}
