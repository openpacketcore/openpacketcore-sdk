//! Self-test outcomes and readiness, with capability withdrawal.
//!
//! A capability is only usable while three things hold at once: the module
//! advertises it, the most recent self-test passed it, and the module
//! currently reports it serviceable. Everything in this module defaults to
//! the withdrawn state, so a capability can never stay advertised past a
//! self-test failure or a loss of readiness.

use std::error::Error;
use std::fmt;

use crate::capability::CapabilitySet;

/// Failure to execute a self-test at all.
///
/// Distinct from a self-test that ran and failed: both withdraw capabilities,
/// but this error means no outcome evidence exists. Callers must treat it as
/// "nothing passed" (fail closed), never as "assume the previous outcome".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfTestError {
    /// The backing module or its transport was unavailable, so the self-test
    /// could not run.
    ModuleUnavailable,
}

impl SelfTestError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ModuleUnavailable => "self_test_module_unavailable",
        }
    }
}

impl fmt::Display for SelfTestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SelfTestError {}

/// Per-capability outcome of one completed self-test run.
///
/// A capability that appears in neither set was not tested; untested and
/// failed capabilities are equally withdrawn from the effective set. The
/// constructor resolves any overlap in favor of `failed`, so a capability can
/// never read as passed and failed at once.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct SelfTestOutcome {
    passed: CapabilitySet,
    failed: CapabilitySet,
}

impl SelfTestOutcome {
    /// Record which capabilities passed and which failed.
    ///
    /// Any capability present in both inputs is recorded as failed only.
    pub const fn new(passed: CapabilitySet, failed: CapabilitySet) -> Self {
        Self {
            passed: passed.difference(failed),
            failed,
        }
    }

    /// Capabilities whose self-test passed.
    pub const fn passed(&self) -> CapabilitySet {
        self.passed
    }

    /// Capabilities whose self-test ran and failed.
    pub const fn failed(&self) -> CapabilitySet {
        self.failed
    }
}

/// Self-test evidence carried by a [`crate::CapabilityReport`].
///
/// The default is [`SelfTestEvidence::NotRun`], which withdraws every
/// capability: evidence must be produced explicitly, never assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfTestEvidence {
    /// No self-test has been run. All capabilities are withdrawn.
    #[default]
    NotRun,
    /// A self-test was attempted but could not execute
    /// ([`SelfTestError::ModuleUnavailable`]). All capabilities are withdrawn.
    Unavailable,
    /// A self-test completed with the recorded per-capability outcome.
    Completed(SelfTestOutcome),
}

impl SelfTestEvidence {
    /// Capabilities the recorded evidence allows: the passed set of a
    /// completed run, and the empty set otherwise (fail closed).
    pub const fn passed_capabilities(&self) -> CapabilitySet {
        match self {
            Self::Completed(outcome) => outcome.passed(),
            Self::NotRun | Self::Unavailable => CapabilitySet::empty(),
        }
    }
}

impl fmt::Display for SelfTestEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRun => formatter.write_str("not_run"),
            Self::Unavailable => formatter.write_str("unavailable"),
            Self::Completed(outcome) => write!(
                formatter,
                "completed(passed={},failed={})",
                outcome.passed(),
                outcome.failed()
            ),
        }
    }
}

/// Which capabilities the module can currently service.
///
/// The default is [`ModuleReadiness::unavailable`]: nothing is serviceable
/// until the module explicitly says so. Losing readiness for a capability
/// removes it from the serviceable set and therefore withdraws it from the
/// effective set, exactly like a self-test failure.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct ModuleReadiness {
    serviceable: CapabilitySet,
}

impl ModuleReadiness {
    /// Nothing is serviceable. Identical to `Default`.
    pub const fn unavailable() -> Self {
        Self {
            serviceable: CapabilitySet::empty(),
        }
    }

    /// The module currently services exactly `serviceable`.
    pub const fn serviceable(serviceable: CapabilitySet) -> Self {
        Self { serviceable }
    }

    /// Capabilities the module can currently service.
    pub const fn serviceable_capabilities(&self) -> CapabilitySet {
        self.serviceable
    }
}

#[cfg(test)]
mod tests {
    use super::{ModuleReadiness, SelfTestError, SelfTestEvidence, SelfTestOutcome};
    use crate::capability::{CapabilitySet, CryptoCapability};

    #[test]
    fn overlapping_pass_and_fail_resolves_to_failed_and_stays_withdrawn() {
        let contested = CapabilitySet::empty().with(CryptoCapability::IkePrf);
        let passed = contested.with(CryptoCapability::Tls);
        let outcome = SelfTestOutcome::new(passed, contested);
        assert!(!outcome.passed().contains(CryptoCapability::IkePrf));
        assert!(outcome.failed().contains(CryptoCapability::IkePrf));
        assert!(outcome.passed().contains(CryptoCapability::Tls));
    }

    #[test]
    fn evidence_defaults_withdraw_every_capability() {
        assert_eq!(SelfTestEvidence::default(), SelfTestEvidence::NotRun);
        for evidence in [SelfTestEvidence::NotRun, SelfTestEvidence::Unavailable] {
            assert!(evidence.passed_capabilities().is_empty());
        }
        assert_eq!(ModuleReadiness::default(), ModuleReadiness::unavailable());
        assert!(ModuleReadiness::default()
            .serviceable_capabilities()
            .is_empty());
    }

    #[test]
    fn self_test_error_code_is_stable_and_display_prints_only_the_code() {
        let error = SelfTestError::ModuleUnavailable;
        assert_eq!(error.as_str(), "self_test_module_unavailable");
        assert_eq!(error.to_string(), "self_test_module_unavailable");
    }
}
