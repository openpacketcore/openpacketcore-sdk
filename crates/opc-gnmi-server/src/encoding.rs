//! Capability-honest gNMI encoding registry.

/// gNMI encodings understood by this crate's capability policy.
///
/// Only [`Encoding::JsonIetf`] and [`Encoding::Json`] are initially advertised.
/// The remaining variants exist so the future protobuf adapter can reject them
/// explicitly without treating unknown numeric enum values as supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encoding {
    /// OpenConfig `JSON_IETF`.
    JsonIetf,
    /// OpenConfig `JSON`.
    Json,
    /// OpenConfig `BYTES`.
    Bytes,
    /// OpenConfig `PROTO`.
    Proto,
    /// OpenConfig `ASCII`.
    Ascii,
}

impl Encoding {
    /// Stable OpenConfig enum label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JsonIetf => "JSON_IETF",
            Self::Json => "JSON",
            Self::Bytes => "BYTES",
            Self::Proto => "PROTO",
            Self::Ascii => "ASCII",
        }
    }

    /// Whether the current SDK has a tested codec for this encoding.
    pub const fn is_initially_supported(self) -> bool {
        matches!(self, Self::JsonIetf | Self::Json)
    }
}

/// Low-cardinality, ordered list of encodings advertised in Capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodingRegistry {
    encodings: Vec<Encoding>,
}

impl EncodingRegistry {
    /// Initial production registry: JSON_IETF first, then JSON.
    pub fn json_only() -> Self {
        Self {
            encodings: vec![Encoding::JsonIetf, Encoding::Json],
        }
    }

    /// Builds a registry from an ordered list, fail-closing on unsupported
    /// encodings or duplicates. This is intentionally strict: adding PROTO,
    /// BYTES, or ASCII requires a tested codec slice first.
    pub fn new(encodings: impl IntoIterator<Item = Encoding>) -> Result<Self, EncodingError> {
        let mut out = Vec::new();
        for encoding in encodings {
            if !encoding.is_initially_supported() {
                return Err(EncodingError::Unsupported(encoding));
            }
            if out.contains(&encoding) {
                return Err(EncodingError::Duplicate(encoding));
            }
            out.push(encoding);
        }
        let registry = Self { encodings: out };
        registry.validate()?;
        Ok(registry)
    }

    /// Advertised encodings in order.
    pub fn encodings(&self) -> &[Encoding] {
        &self.encodings
    }

    /// Whether this registry supports a requested encoding.
    pub fn supports(&self, encoding: Encoding) -> bool {
        self.encodings.contains(&encoding)
    }

    /// Validates that the registry is non-empty and starts with JSON_IETF.
    pub fn validate(&self) -> Result<(), EncodingError> {
        if self.encodings.is_empty() {
            return Err(EncodingError::Empty);
        }
        if self.encodings[0] != Encoding::JsonIetf {
            return Err(EncodingError::JsonIetfNotFirst);
        }
        Ok(())
    }
}

impl Default for EncodingRegistry {
    fn default() -> Self {
        Self::json_only()
    }
}

/// Invalid encoding-registry configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EncodingError {
    /// No encodings were configured.
    #[error("gNMI encoding registry is empty")]
    Empty,
    /// JSON_IETF must be first for the initial production profile.
    #[error("gNMI JSON_IETF encoding must be advertised first")]
    JsonIetfNotFirst,
    /// The current SDK has no tested codec for this encoding.
    #[error("gNMI encoding is not supported")]
    Unsupported(Encoding),
    /// The registry listed an encoding more than once.
    #[error("gNMI encoding was listed more than once")]
    Duplicate(Encoding),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_json_ietf_then_json() {
        let registry = EncodingRegistry::default();
        assert_eq!(registry.encodings(), &[Encoding::JsonIetf, Encoding::Json]);
        assert!(registry.supports(Encoding::JsonIetf));
        assert!(registry.supports(Encoding::Json));
        assert!(!registry.supports(Encoding::Proto));
    }

    #[test]
    fn rejects_unsupported_and_misordered_encodings() {
        assert_eq!(
            EncodingRegistry::new([Encoding::Proto]).unwrap_err(),
            EncodingError::Unsupported(Encoding::Proto)
        );
        assert_eq!(
            EncodingRegistry::new([Encoding::Json, Encoding::JsonIetf]).unwrap_err(),
            EncodingError::JsonIetfNotFirst
        );
        assert_eq!(
            EncodingRegistry::new([Encoding::JsonIetf, Encoding::JsonIetf]).unwrap_err(),
            EncodingError::Duplicate(Encoding::JsonIetf)
        );
    }
}
