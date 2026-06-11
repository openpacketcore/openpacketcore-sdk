use serde::{Deserialize, Serialize};

/// Conformance status of a requirement.
///
/// Per RFC 006 §4.1 and §5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConformanceStatus {
    /// Code exists for the requirement.
    Implemented,

    /// Automated tests exercise the requirement.
    Tested,

    /// Some required behavior is missing.
    Partial,

    /// No implementation exists.
    NotImplemented,

    /// Requirement does not apply.
    NotApplicable,

    /// Known missing behavior with owner and mitigation.
    Gap,

    /// Temporary exception approved by policy.
    Waived,

    /// Code + passing tests + no blocking gaps (calculated).
    Full,

    /// Code + no tests (calculated).
    ImplementedUntested,
}

/// Inputs used to compute the effective [`ConformanceStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatusInputs {
    pub has_code: bool,
    pub has_tests: bool,
    pub has_blocking_gap: bool,
    pub has_gap: bool,
    pub has_waiver: bool,
    pub reviewed_na: bool,
}

/// Calculates the effective conformance status from raw inputs.
///
/// Rules (from RFC 006 §5.4):
///
/// | Inputs | Result |
/// | :--- | :--- |
/// | code + passing tests + no blocking gaps | `Full` |
/// | code + some tests + open nonblocking gaps | `Partial` |
/// | code + no tests | `ImplementedUntested` |
/// | gap with no code | `NotImplemented` |
/// | reviewed N/A record | `NotApplicable` |
/// | approved waiver | `Waived` |
pub fn calculate_status(inputs: &StatusInputs) -> ConformanceStatus {
    if inputs.reviewed_na {
        return ConformanceStatus::NotApplicable;
    }

    if inputs.has_waiver {
        return ConformanceStatus::Waived;
    }

    if !inputs.has_code {
        return ConformanceStatus::NotImplemented;
    }

    if inputs.has_tests && !inputs.has_blocking_gap && !inputs.has_gap {
        return ConformanceStatus::Full;
    }

    if inputs.has_tests && (inputs.has_blocking_gap || inputs.has_gap) {
        return ConformanceStatus::Partial;
    }

    if inputs.has_gap {
        return ConformanceStatus::Partial;
    }

    ConformanceStatus::ImplementedUntested
}
