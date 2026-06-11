use opc_data_governance::{DataClass, IdentifierType};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Redaction levels from RFC 010 §6.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RedactionLevel {
    /// Omit the field entirely.
    Drop,
    /// Show a fixed placeholder.
    Mask,
    /// Show class and presence only.
    Class,
    /// Show approximate length bucket.
    LengthClass,
    /// Show keyed digest.
    Digest,
    /// Show raw value (allowed only by explicit policy).
    ///
    /// Cleartext is forbidden for [`DataClass::SecuritySecret`] and restricted
    /// for [`DataClass::LawfulIntercept`] per RFC 010 §6. The [`redact`]
    /// function enforces these guards by downgrading to [`RedactedValue::Mask`]
    /// when policy denies cleartext for the given class.
    Cleartext,
}

impl RedactionLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Drop => "drop",
            Self::Mask => "mask",
            Self::Class => "class",
            Self::LengthClass => "length-class",
            Self::Digest => "digest",
            Self::Cleartext => "cleartext",
        }
    }
}

impl fmt::Display for RedactionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Approximate length buckets for the [`RedactionLevel::LengthClass`] renderer.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LengthBucket {
    Empty,
    Short,
    Medium,
    Long,
    ExtraLong,
}

impl LengthBucket {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Short => "short",
            Self::Medium => "medium",
            Self::Long => "long",
            Self::ExtraLong => "extra-long",
        }
    }
}

impl fmt::Display for LengthBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<usize> for LengthBucket {
    fn from(len: usize) -> Self {
        match len {
            0 => Self::Empty,
            1..=8 => Self::Short,
            9..=16 => Self::Medium,
            17..=32 => Self::Long,
            _ => Self::ExtraLong,
        }
    }
}

/// The result of applying a redaction level to a value.
///
/// `Debug` and `Display` implementations are guaranteed never to emit the raw
/// underlying value. For the [`RedactedValue::Cleartext`] variant the original
/// value is retained so that authorized downstream code can access it via
/// [`RedactedValue::expose`], but formatting still yields a safe placeholder.
#[derive(Clone, PartialEq, Eq)]
pub enum RedactedValue {
    Dropped,
    Mask,
    Class(DataClass),
    LengthClass(DataClass, LengthBucket),
    Digest(String),
    /// Carries the authorized cleartext value, but `Display` still yields a
    /// safe placeholder. Call [`RedactedValue::expose`] to retrieve the value
    /// when policy explicitly permits it.
    Cleartext(String),
}

impl RedactedValue {
    /// Returns the inner cleartext value when this variant is
    /// [`RedactedValue::Cleartext`], otherwise `None`.
    pub fn expose(&self) -> Option<&str> {
        match self {
            Self::Cleartext(v) => Some(v),
            _ => None,
        }
    }
}

impl fmt::Debug for RedactedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dropped => f.debug_struct("Dropped").finish(),
            Self::Mask => f.debug_struct("Mask").finish(),
            Self::Class(class) => f.debug_tuple("Class").field(class).finish(),
            Self::LengthClass(class, bucket) => f
                .debug_tuple("LengthClass")
                .field(class)
                .field(bucket)
                .finish(),
            Self::Digest(digest) => f.debug_tuple("Digest").field(digest).finish(),
            Self::Cleartext(_) => f
                .debug_struct("Cleartext")
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}

impl fmt::Display for RedactedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dropped => f.write_str("<dropped>"),
            Self::Mask => f.write_str("<redacted>"),
            Self::Class(class) => write!(f, "<{}>", class),
            Self::LengthClass(class, bucket) => write!(f, "<{}:{}>", class, bucket),
            Self::Digest(digest) => write!(f, "<digest:{}>", digest),
            Self::Cleartext(_) => f.write_str("<cleartext>"),
        }
    }
}

/// Apply a redaction level to a raw value.
///
/// For [`RedactionLevel::Digest`] the `digest_key` must be provided and
/// `id_type` must be `Some` or the function returns [`RedactedValue::Mask`] as
/// a safe fallback.
///
/// For [`RedactionLevel::Cleartext`] the function enforces RFC 010 §6 policy:
/// `security-secret` is always denied and `lawful-intercept` is always denied
/// (restricted) in the absence of an explicit policy engine. Denied cleartext
/// requests fall back to [`RedactedValue::Mask`].
pub fn redact(
    value: &str,
    class: DataClass,
    level: RedactionLevel,
    id_type: Option<IdentifierType>,
    digest_key: Option<&super::DigestKey>,
) -> RedactedValue {
    match level {
        RedactionLevel::Drop => RedactedValue::Dropped,
        RedactionLevel::Mask => RedactedValue::Mask,
        RedactionLevel::Class => RedactedValue::Class(class),
        RedactionLevel::LengthClass => RedactedValue::LengthClass(class, value.len().into()),
        RedactionLevel::Digest => {
            if let (Some(key), Some(id_type)) = (digest_key, id_type) {
                RedactedValue::Digest(super::compute_digest(key, class, id_type, value))
            } else {
                RedactedValue::Mask
            }
        }
        RedactionLevel::Cleartext => {
            if class.allows_cleartext() {
                RedactedValue::Cleartext(value.to_string())
            } else {
                RedactedValue::Mask
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_data_governance::{DataClass, IdentifierType};

    #[test]
    fn drop_level_omits_field() {
        let r = redact(
            "sensitive",
            DataClass::SubscriberId,
            RedactionLevel::Drop,
            None,
            None,
        );
        assert_eq!(r, RedactedValue::Dropped);
        assert_eq!(r.to_string(), "<dropped>");
    }

    #[test]
    fn mask_level_shows_placeholder() {
        let r = redact(
            "sensitive",
            DataClass::SubscriberId,
            RedactionLevel::Mask,
            None,
            None,
        );
        assert_eq!(r, RedactedValue::Mask);
        assert_eq!(r.to_string(), "<redacted>");
    }

    #[test]
    fn class_level_shows_class_only() {
        let r = redact(
            "sensitive",
            DataClass::SubscriberId,
            RedactionLevel::Class,
            None,
            None,
        );
        assert_eq!(r, RedactedValue::Class(DataClass::SubscriberId));
        assert_eq!(r.to_string(), "<subscriber-id>");
    }

    #[test]
    fn length_class_level_shows_bucket() {
        let r = redact(
            "123456789012345",
            DataClass::SubscriberId,
            RedactionLevel::LengthClass,
            None,
            None,
        );
        assert_eq!(
            r,
            RedactedValue::LengthClass(DataClass::SubscriberId, LengthBucket::Medium)
        );
        assert_eq!(r.to_string(), "<subscriber-id:medium>");
    }

    #[test]
    fn digest_level_shows_stable_digest() {
        let key = super::super::DigestKey::new([0xab; 32]);
        let r = redact(
            "123456789012345",
            DataClass::SubscriberId,
            RedactionLevel::Digest,
            Some(IdentifierType::Supi),
            Some(&key),
        );
        match &r {
            RedactedValue::Digest(d) => {
                assert_eq!(d.len(), 64);
                assert!(r.to_string().starts_with("<digest:"));
            }
            other => panic!("expected Digest, got {:?}", other),
        }
    }

    #[test]
    fn digest_level_fallback_to_mask_when_key_missing() {
        let r = redact(
            "123456789012345",
            DataClass::SubscriberId,
            RedactionLevel::Digest,
            Some(IdentifierType::Supi),
            None,
        );
        assert_eq!(r, RedactedValue::Mask);
    }

    #[test]
    fn digest_level_fallback_to_mask_when_id_type_missing() {
        let key = super::super::DigestKey::new([0xab; 32]);
        let r = redact(
            "123456789012345",
            DataClass::SubscriberId,
            RedactionLevel::Digest,
            None,
            Some(&key),
        );
        assert_eq!(r, RedactedValue::Mask);
    }

    #[test]
    fn cleartext_carries_value_for_allowed_class() {
        let r = redact(
            "visible",
            DataClass::Public,
            RedactionLevel::Cleartext,
            None,
            None,
        );
        assert_eq!(r.expose(), Some("visible"));
        assert_eq!(r.to_string(), "<cleartext>");
    }

    #[test]
    fn cleartext_denied_for_security_secret() {
        let r = redact(
            "secret",
            DataClass::SecuritySecret,
            RedactionLevel::Cleartext,
            None,
            None,
        );
        assert_eq!(r, RedactedValue::Mask);
        assert_eq!(r.expose(), None);
    }

    #[test]
    fn cleartext_denied_for_lawful_intercept() {
        let r = redact(
            "li-target",
            DataClass::LawfulIntercept,
            RedactionLevel::Cleartext,
            None,
            None,
        );
        assert_eq!(r, RedactedValue::Mask);
        assert_eq!(r.expose(), None);
    }

    #[test]
    fn raw_value_never_appears_in_display() {
        let raw = "123456789012345";
        for level in [
            RedactionLevel::Drop,
            RedactionLevel::Mask,
            RedactionLevel::Class,
            RedactionLevel::LengthClass,
            RedactionLevel::Digest,
            RedactionLevel::Cleartext,
        ] {
            let key = super::super::DigestKey::new([0xcd; 32]);
            let id_type = if level == RedactionLevel::Digest {
                Some(IdentifierType::Supi)
            } else {
                None
            };
            let r = redact(raw, DataClass::SubscriberId, level, id_type, Some(&key));
            let display = r.to_string();
            assert!(
                !display.contains(raw),
                "level {:?} leaked raw value in display",
                level
            );
            let debug = format!("{:?}", r);
            assert!(
                !debug.contains(raw),
                "level {:?} leaked raw value in debug",
                level
            );
        }
    }

    #[test]
    fn length_bucket_boundaries() {
        assert_eq!(LengthBucket::from(0_usize), LengthBucket::Empty);
        assert_eq!(LengthBucket::from(1_usize), LengthBucket::Short);
        assert_eq!(LengthBucket::from(8_usize), LengthBucket::Short);
        assert_eq!(LengthBucket::from(9_usize), LengthBucket::Medium);
        assert_eq!(LengthBucket::from(16_usize), LengthBucket::Medium);
        assert_eq!(LengthBucket::from(17_usize), LengthBucket::Long);
        assert_eq!(LengthBucket::from(32_usize), LengthBucket::Long);
        assert_eq!(LengthBucket::from(33_usize), LengthBucket::ExtraLong);
    }
}
