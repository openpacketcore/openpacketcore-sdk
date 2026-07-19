//! Fail-closed capability policy and admission.

use std::error::Error;
use std::fmt;

use crate::capability::{CapabilitySet, CryptoCapability};
use crate::identity::{ProviderIdentity, ValidationState};
use crate::report::CapabilityReport;

/// Which capabilities (and optionally a declared validation state) a
/// deployment requires from its selected module.
///
/// The default policy requires nothing, so ordinary non-validated modules
/// compose with zero ceremony. A policy that does require something **fails
/// closed**: [`Self::admit`] rejects a module whose effective capabilities
/// fall short, and there is no fallback — this crate offers no way to route a
/// required operation anywhere other than an admitted module.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderPolicy {
    required: CapabilitySet,
    require_declared_validation: bool,
}

impl ProviderPolicy {
    /// A policy that requires nothing. Identical to `Default`.
    pub const fn new() -> Self {
        Self {
            required: CapabilitySet::empty(),
            require_declared_validation: false,
        }
    }

    /// Also require `capability` to be effective at admission.
    pub const fn require(self, capability: CryptoCapability) -> Self {
        Self {
            required: self.required.with(capability),
            require_declared_validation: self.require_declared_validation,
        }
    }

    /// Also require every capability in `capabilities`.
    pub const fn require_all(self, capabilities: CapabilitySet) -> Self {
        Self {
            required: self.required.union(capabilities),
            require_declared_validation: self.require_declared_validation,
        }
    }

    /// Also require the module to self-declare validated status.
    ///
    /// This gates on the module's declaration only; the SDK does not verify
    /// the claim (see [`ValidationState`]).
    pub const fn require_declared_validation(self) -> Self {
        Self {
            required: self.required,
            require_declared_validation: true,
        }
    }

    /// Capabilities this policy requires.
    pub const fn required_capabilities(&self) -> CapabilitySet {
        self.required
    }

    /// Whether this policy requires a self-declared validated module.
    #[must_use]
    pub const fn requires_declared_validation(&self) -> bool {
        self.require_declared_validation
    }

    /// Check a module's evidence against this policy, before any operation.
    ///
    /// Admission is the only source of [`PolicyAdmission`] values, and later
    /// slices bind operations to an admission, so a rejection here structurally
    /// prevents every gated operation — nothing can fall back to another code
    /// path. The check runs against [`CapabilityReport::effective_capabilities`],
    /// so an advertised capability withdrawn by a failed self-test or lost
    /// readiness rejects exactly like one that was never advertised.
    pub fn admit(&self, report: &CapabilityReport) -> Result<PolicyAdmission, PolicyError> {
        let missing = self.required.difference(report.effective_capabilities());
        if !missing.is_empty() {
            return Err(PolicyError::CapabilityUnavailable { missing });
        }
        if self.require_declared_validation && !report.validation_state().is_declared_validated() {
            return Err(PolicyError::ValidationNotDeclared);
        }
        Ok(PolicyAdmission {
            identity: report.identity().clone(),
            validation: report.validation_state().clone(),
            granted: self.required,
        })
    }
}

/// Typed fail-closed rejection from [`ProviderPolicy::admit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// One or more required capabilities are not effective on the module.
    CapabilityUnavailable {
        /// Required capabilities that are missing from the effective set.
        missing: CapabilitySet,
    },
    /// The policy requires a self-declared validated module and the module
    /// declares no validation.
    ValidationNotDeclared,
}

impl PolicyError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CapabilityUnavailable { .. } => "policy_capability_unavailable",
            Self::ValidationNotDeclared => "policy_validation_not_declared",
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for PolicyError {}

/// Proof that a policy admitted a module, scoped to the granted capabilities.
///
/// Only [`ProviderPolicy::admit`] can construct this value; there is no other
/// constructor and no `Default`. Later slices accept an admission wherever a
/// security-critical operation is bound to the module, which makes "operation
/// without admission" unrepresentable. The granted set is exactly the
/// policy's required set (least privilege): an operation needing a capability
/// the policy never named must fail closed rather than assume it.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAdmission {
    identity: ProviderIdentity,
    validation: ValidationState,
    granted: CapabilitySet,
}

impl PolicyAdmission {
    /// Identity of the admitted module.
    pub fn identity(&self) -> &ProviderIdentity {
        &self.identity
    }

    /// Validation state the admitted module declared at admission time.
    #[must_use]
    pub fn validation_state(&self) -> &ValidationState {
        &self.validation
    }

    /// Capabilities this admission grants (the policy's required set).
    pub const fn granted_capabilities(&self) -> CapabilitySet {
        self.granted
    }
}

#[cfg(test)]
mod tests {
    use super::{PolicyError, ProviderPolicy};
    use crate::capability::{CapabilitySet, CryptoCapability};
    use crate::identity::{ProviderIdentity, ValidationState};
    use crate::report::CapabilityReport;
    use crate::selftest::{ModuleReadiness, SelfTestEvidence, SelfTestOutcome};

    fn report_with(effective: CapabilitySet, validation: ValidationState) -> CapabilityReport {
        let identity = match ProviderIdentity::from_parts("policy fixture", "0.0.1") {
            Ok(identity) => identity,
            Err(error) => panic!("valid identity labels: {error}"),
        };
        CapabilityReport::new(
            identity,
            validation,
            effective,
            SelfTestEvidence::Completed(SelfTestOutcome::new(effective, CapabilitySet::empty())),
            ModuleReadiness::serviceable(effective),
        )
    }

    #[test]
    fn the_default_policy_admits_a_bare_module_and_grants_nothing() {
        let report = report_with(CapabilitySet::empty(), ValidationState::NotValidated);
        let admission = match ProviderPolicy::default().admit(&report) {
            Ok(admission) => admission,
            Err(error) => panic!("default policy must admit: {error}"),
        };
        assert!(admission.granted_capabilities().is_empty());
        assert_eq!(admission.identity(), report.identity());
        assert_eq!(admission.validation_state(), &ValidationState::NotValidated);
    }

    #[test]
    fn a_missing_required_capability_rejects_with_the_exact_missing_set() {
        let policy = ProviderPolicy::new()
            .require(CryptoCapability::Tls)
            .require(CryptoCapability::IkeDiffieHellman);
        let report = report_with(
            CapabilitySet::empty().with(CryptoCapability::Tls),
            ValidationState::NotValidated,
        );
        assert_eq!(
            policy.admit(&report),
            Err(PolicyError::CapabilityUnavailable {
                missing: CapabilitySet::empty().with(CryptoCapability::IkeDiffieHellman),
            })
        );
    }

    #[test]
    fn requiring_declared_validation_rejects_a_non_validated_module() {
        let policy = ProviderPolicy::new().require_declared_validation();
        let report = report_with(CapabilitySet::empty(), ValidationState::NotValidated);
        assert_eq!(
            policy.admit(&report),
            Err(PolicyError::ValidationNotDeclared)
        );

        let declared = report_with(
            CapabilitySet::empty(),
            ValidationState::DeclaredValidated { reference: None },
        );
        assert!(policy.admit(&declared).is_ok());
    }

    #[test]
    fn policy_error_codes_are_stable_and_display_prints_only_the_code() {
        let cases = [
            (
                PolicyError::CapabilityUnavailable {
                    missing: CapabilitySet::empty().with(CryptoCapability::Tls),
                },
                "policy_capability_unavailable",
            ),
            (
                PolicyError::ValidationNotDeclared,
                "policy_validation_not_declared",
            ),
        ];
        for (error, code) in cases {
            assert_eq!(error.as_str(), code);
            assert_eq!(error.to_string(), code);
        }
    }
}
