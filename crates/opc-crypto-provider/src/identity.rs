//! Provider identity and self-declared validation state.
//!
//! Identity labels are bounded, printable-ASCII strings so every capability
//! report stays log-safe and bounded in size. Labels are identity evidence,
//! never secrets: callers must not place key material or other sensitive data
//! in a provider name, version, or validation reference.

use std::error::Error;
use std::fmt;

/// Failure while validating a bounded provider label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderLabelError {
    /// The label was empty.
    Empty,
    /// The label exceeded its documented byte bound.
    TooLong {
        /// Maximum permitted length in bytes.
        max: usize,
        /// Supplied length in bytes.
        actual: usize,
    },
    /// The label contained a byte outside printable ASCII, or leading or
    /// trailing whitespace.
    InvalidCharacter,
}

impl ProviderLabelError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Empty => "provider_label_empty",
            Self::TooLong { .. } => "provider_label_too_long",
            Self::InvalidCharacter => "provider_label_invalid_character",
        }
    }
}

impl fmt::Display for ProviderLabelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for ProviderLabelError {}

fn validate_label(value: &str, max: usize) -> Result<(), ProviderLabelError> {
    if value.is_empty() {
        return Err(ProviderLabelError::Empty);
    }
    if value.len() > max {
        return Err(ProviderLabelError::TooLong {
            max,
            actual: value.len(),
        });
    }
    if value.bytes().any(|byte| !(0x20..=0x7e).contains(&byte)) {
        return Err(ProviderLabelError::InvalidCharacter);
    }
    if value.starts_with(' ') || value.ends_with(' ') {
        return Err(ProviderLabelError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! bounded_label {
    ($(#[$doc:meta])* $name:ident, $max:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Maximum permitted length in bytes.
            pub const MAX_LEN: usize = $max;

            /// Validate and wrap a label.
            ///
            /// Accepts one to `MAX_LEN` bytes of printable ASCII
            /// (`0x20..=0x7e`) without leading or trailing spaces.
            pub fn new(value: impl Into<String>) -> Result<Self, ProviderLabelError> {
                let value = value.into();
                validate_label(&value, Self::MAX_LEN)?;
                Ok(Self(value))
            }

            /// Borrow the validated label text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }
    };
}

bounded_label!(
    /// Stable, non-secret name of a cryptographic module (at most 64 bytes).
    ProviderName,
    64
);

bounded_label!(
    /// Non-secret version label of a cryptographic module (at most 32 bytes).
    ProviderVersion,
    32
);

bounded_label!(
    /// Bounded, module-self-declared validation program or certificate
    /// reference (at most 128 bytes).
    ///
    /// Recorded verbatim as evidence. The SDK never verifies the reference and
    /// never implies it is externally certified.
    ValidationReference,
    128
);

/// Stable identity of the cryptographic module that answered a report.
///
/// Bound into every [`crate::CapabilityReport`] so a consumer can always tell
/// *which* module and version produced a piece of evidence.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct ProviderIdentity {
    name: ProviderName,
    version: ProviderVersion,
}

impl ProviderIdentity {
    /// Bind a validated name and version together.
    pub const fn new(name: ProviderName, version: ProviderVersion) -> Self {
        Self { name, version }
    }

    /// Validate raw label text and bind it into an identity.
    pub fn from_parts(name: &str, version: &str) -> Result<Self, ProviderLabelError> {
        Ok(Self::new(
            ProviderName::new(name)?,
            ProviderVersion::new(version)?,
        ))
    }

    /// Module name.
    #[must_use]
    pub fn name(&self) -> &ProviderName {
        &self.name
    }

    /// Module version label.
    #[must_use]
    pub fn version(&self) -> &ProviderVersion {
        &self.version
    }
}

impl fmt::Display for ProviderIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.name, self.version)
    }
}

/// Whether a module claims validated status, as declared by the module itself.
///
/// The default is [`ValidationState::NotValidated`]: composing an ordinary
/// non-validated module claims nothing and requires nothing. A module may
/// instead declare that it operates in a validated mode; this crate records
/// that declaration verbatim as evidence. **The SDK never verifies the claim,
/// never certifies a module or deployment, and never implies that a declared
/// status is externally certified.**
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationState {
    /// The module makes no validation claim. This is the default.
    #[default]
    NotValidated,
    /// The module self-declares that it operates in a validated mode.
    DeclaredValidated {
        /// Optional self-declared program or certificate reference.
        reference: Option<ValidationReference>,
    },
}

impl ValidationState {
    /// Stable machine-readable state code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotValidated => "not_validated",
            Self::DeclaredValidated { .. } => "declared_validated",
        }
    }

    /// Returns `true` when the module self-declares validated status.
    #[must_use]
    pub const fn is_declared_validated(&self) -> bool {
        matches!(self, Self::DeclaredValidated { .. })
    }
}

impl fmt::Display for ValidationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ProviderIdentity, ProviderLabelError, ProviderName, ProviderVersion, ValidationReference,
        ValidationState,
    };

    #[test]
    fn labels_reject_empty_oversized_and_unprintable_values() {
        assert_eq!(ProviderName::new(""), Err(ProviderLabelError::Empty));
        assert_eq!(
            ProviderName::new("a".repeat(ProviderName::MAX_LEN + 1)),
            Err(ProviderLabelError::TooLong {
                max: ProviderName::MAX_LEN,
                actual: ProviderName::MAX_LEN + 1,
            })
        );
        for invalid in [
            "line\nbreak",
            "nul\0byte",
            "tab\tbyte",
            " padded",
            "padded ",
        ] {
            assert_eq!(
                ProviderVersion::new(invalid),
                Err(ProviderLabelError::InvalidCharacter),
                "{invalid:?} must be rejected"
            );
        }
        assert_eq!(
            ValidationReference::new("x".repeat(ValidationReference::MAX_LEN))
                .map(|reference| reference.as_str().len()),
            Ok(ValidationReference::MAX_LEN)
        );
    }

    #[test]
    fn identity_binds_name_and_version_and_renders_stably() {
        let identity = match ProviderIdentity::from_parts("acme hsm", "3.1.4") {
            Ok(identity) => identity,
            Err(error) => panic!("valid identity labels: {error}"),
        };
        assert_eq!(identity.name().as_str(), "acme hsm");
        assert_eq!(identity.version().as_str(), "3.1.4");
        assert_eq!(identity.to_string(), "acme hsm/3.1.4");
    }

    #[test]
    fn validation_state_defaults_to_not_validated_and_never_claims_more() {
        assert_eq!(ValidationState::default(), ValidationState::NotValidated);
        assert!(!ValidationState::default().is_declared_validated());
        assert_eq!(ValidationState::NotValidated.as_str(), "not_validated");

        let declared = ValidationState::DeclaredValidated { reference: None };
        assert!(declared.is_declared_validated());
        assert_eq!(declared.as_str(), "declared_validated");
    }

    #[test]
    fn label_error_codes_are_stable_and_display_only_the_code() {
        let cases = [
            (ProviderLabelError::Empty, "provider_label_empty"),
            (
                ProviderLabelError::TooLong { max: 1, actual: 2 },
                "provider_label_too_long",
            ),
            (
                ProviderLabelError::InvalidCharacter,
                "provider_label_invalid_character",
            ),
        ];
        for (error, code) in cases {
            assert_eq!(error.as_str(), code);
            assert_eq!(error.to_string(), code);
        }
    }
}
