//! Redaction-safe, bounded capability evidence.

use std::fmt;

use crate::capability::CapabilitySet;
use crate::identity::{ProviderIdentity, ValidationState};
use crate::provider::CryptoModule;
use crate::selftest::{ModuleReadiness, SelfTestEvidence};

/// Evidence binding capabilities to a module's identity, version, and
/// validation state.
///
/// Suitable for readiness endpoints and release artifacts: every field is
/// bounded at construction (labels are bounded printable ASCII, capability
/// sets are fixed-width), the whole report serializes within
/// [`Self::MAX_JSON_BYTES`], and no type in this crate can hold key material,
/// so the report cannot leak any.
///
/// The report records the module's **self-declared** identity, version, and
/// validation state as evidence. It never asserts that any declaration is
/// externally certified.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    identity: ProviderIdentity,
    validation: ValidationState,
    advertised: CapabilitySet,
    self_test: SelfTestEvidence,
    readiness: ModuleReadiness,
}

impl CapabilityReport {
    /// Guaranteed upper bound, in bytes, of this report serialized as JSON
    /// with `serde_json`, for any inputs the constructors accept.
    pub const MAX_JSON_BYTES: usize = 2048;

    /// Assemble a report from separately gathered evidence.
    pub const fn new(
        identity: ProviderIdentity,
        validation: ValidationState,
        advertised: CapabilitySet,
        self_test: SelfTestEvidence,
        readiness: ModuleReadiness,
    ) -> Self {
        Self {
            identity,
            validation,
            advertised,
            self_test,
            readiness,
        }
    }

    /// Identity of the module this report describes.
    pub fn identity(&self) -> &ProviderIdentity {
        &self.identity
    }

    /// The module's self-declared validation state.
    #[must_use]
    pub fn validation_state(&self) -> &ValidationState {
        &self.validation
    }

    /// Capabilities the module advertises.
    pub const fn advertised_capabilities(&self) -> CapabilitySet {
        self.advertised
    }

    /// Recorded self-test evidence.
    #[must_use]
    pub const fn self_test(&self) -> &SelfTestEvidence {
        &self.self_test
    }

    /// Recorded readiness evidence.
    pub const fn readiness(&self) -> &ModuleReadiness {
        &self.readiness
    }

    /// Capabilities that are actually usable right now.
    ///
    /// Fail-closed intersection: a capability must be advertised **and** have
    /// passed the recorded self-test **and** be currently serviceable. A
    /// self-test failure, a self-test that never ran or could not run, or a
    /// loss of readiness therefore withdraws the capability here even while
    /// it stays advertised.
    pub fn effective_capabilities(&self) -> CapabilitySet {
        self.advertised
            .intersection(self.self_test.passed_capabilities())
            .intersection(self.readiness.serviceable_capabilities())
    }
}

impl fmt::Display for CapabilityReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "provider={} validation={} advertised={} self_test={} serviceable={} effective={}",
            self.identity,
            self.validation,
            self.advertised,
            self.self_test,
            self.readiness.serviceable_capabilities(),
            self.effective_capabilities(),
        )
    }
}

impl serde::Serialize for CapabilityReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CapabilityReport", 6)?;
        state.serialize_field("provider", &self.identity)?;
        state.serialize_field("validation", &self.validation)?;
        state.serialize_field("advertised", &self.advertised)?;
        state.serialize_field("self_test", &self.self_test)?;
        state.serialize_field("serviceable", &self.readiness.serviceable_capabilities())?;
        state.serialize_field("effective", &self.effective_capabilities())?;
        state.end()
    }
}

/// Probe a module and assemble its current [`CapabilityReport`].
///
/// Runs the module's self-test, then snapshots readiness afterwards so a
/// self-test that degrades the module is reflected. A self-test that cannot
/// run is recorded as [`SelfTestEvidence::Unavailable`], which withdraws every
/// capability from the effective set — the error is converted into explicit
/// fail-closed evidence, never discarded silently.
pub async fn probe_capability_report<M>(module: &M) -> CapabilityReport
where
    M: CryptoModule + ?Sized,
{
    let self_test = match module.self_test().await {
        Ok(outcome) => SelfTestEvidence::Completed(outcome),
        Err(_) => SelfTestEvidence::Unavailable,
    };
    CapabilityReport::new(
        module.identity(),
        module.validation_state(),
        module.advertised_capabilities(),
        self_test,
        module.readiness(),
    )
}

#[cfg(test)]
mod tests {
    use super::CapabilityReport;
    use crate::capability::{CapabilitySet, CryptoCapability};
    use crate::identity::{
        ProviderIdentity, ProviderName, ProviderVersion, ValidationReference, ValidationState,
    };
    use crate::selftest::{ModuleReadiness, SelfTestEvidence, SelfTestOutcome};

    fn identity() -> ProviderIdentity {
        match ProviderIdentity::from_parts("acme hsm", "3.1.4") {
            Ok(identity) => identity,
            Err(error) => panic!("valid identity labels: {error}"),
        }
    }

    #[test]
    fn effective_set_is_the_intersection_of_advertised_passed_and_serviceable() {
        let advertised = CapabilitySet::from_slice(&[
            CryptoCapability::Tls,
            CryptoCapability::IkePrf,
            CryptoCapability::ApprovedEntropy,
        ]);
        let passed = advertised.without(CryptoCapability::IkePrf);
        let serviceable = advertised.without(CryptoCapability::ApprovedEntropy);
        let report = CapabilityReport::new(
            identity(),
            ValidationState::NotValidated,
            advertised,
            SelfTestEvidence::Completed(SelfTestOutcome::new(passed, CapabilitySet::empty())),
            ModuleReadiness::serviceable(serviceable),
        );
        assert_eq!(
            report.effective_capabilities(),
            CapabilitySet::empty().with(CryptoCapability::Tls)
        );
    }

    #[test]
    fn missing_self_test_or_readiness_evidence_withdraws_everything() {
        let advertised = CapabilitySet::from_slice(CryptoCapability::ALL);
        for (self_test, readiness) in [
            (
                SelfTestEvidence::NotRun,
                ModuleReadiness::serviceable(advertised),
            ),
            (
                SelfTestEvidence::Unavailable,
                ModuleReadiness::serviceable(advertised),
            ),
            (
                SelfTestEvidence::Completed(SelfTestOutcome::new(
                    advertised,
                    CapabilitySet::empty(),
                )),
                ModuleReadiness::unavailable(),
            ),
        ] {
            let report = CapabilityReport::new(
                identity(),
                ValidationState::NotValidated,
                advertised,
                self_test,
                readiness,
            );
            assert!(
                report.effective_capabilities().is_empty(),
                "withdrawn evidence must leave nothing effective: {report}"
            );
        }
    }

    #[test]
    fn maximal_report_serializes_within_the_documented_json_bound() {
        let name = match ProviderName::new("N".repeat(ProviderName::MAX_LEN)) {
            Ok(name) => name,
            Err(error) => panic!("max-length name is valid: {error}"),
        };
        let version = match ProviderVersion::new("V".repeat(ProviderVersion::MAX_LEN)) {
            Ok(version) => version,
            Err(error) => panic!("max-length version is valid: {error}"),
        };
        let reference = match ValidationReference::new("R".repeat(ValidationReference::MAX_LEN)) {
            Ok(reference) => reference,
            Err(error) => panic!("max-length reference is valid: {error}"),
        };
        let everything = CapabilitySet::from_slice(CryptoCapability::ALL);
        let report = CapabilityReport::new(
            ProviderIdentity::new(name, version),
            ValidationState::DeclaredValidated {
                reference: Some(reference),
            },
            everything,
            SelfTestEvidence::Completed(SelfTestOutcome::new(everything, everything)),
            ModuleReadiness::serviceable(everything),
        );
        let json = match serde_json::to_string(&report) {
            Ok(json) => json,
            Err(error) => panic!("report must serialize: {error}"),
        };
        assert!(
            json.len() <= CapabilityReport::MAX_JSON_BYTES,
            "serialized report ({} bytes) exceeded MAX_JSON_BYTES",
            json.len()
        );
        for rendered in [json, format!("{report:?}"), report.to_string()] {
            assert!(
                rendered.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
                "report renderings must stay printable ASCII"
            );
        }
    }
}
