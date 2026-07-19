//! Test-only configurable cryptographic-module fixture.
//!
//! [`FakeCryptoModule`] performs no cryptography. It exists so tests can prove
//! the fail-closed contract: satisfy an advertised capability set, then drop a
//! capability, fail or disable the self-test, or withdraw readiness, and
//! observe the capability disappear from the effective set and from policy
//! admission.

use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;

use crate::capability::CapabilitySet;
use crate::identity::{ProviderIdentity, ValidationState};
use crate::provider::CryptoModule;
use crate::selftest::{ModuleReadiness, SelfTestError, SelfTestOutcome};

#[derive(Default)]
struct FakeState {
    self_test_failures: CapabilitySet,
    self_test_unavailable: bool,
    unserviceable: CapabilitySet,
}

/// Configurable in-process [`CryptoModule`] fixture.
///
/// Freshly constructed, it advertises nothing and declares
/// [`ValidationState::NotValidated`]. With advertised capabilities configured,
/// it passes its self-test for all of them and reports them all serviceable
/// until a test injects a failure through [`Self::fail_self_test_for`],
/// [`Self::make_self_test_unavailable`], or [`Self::withdraw_serviceability`].
pub struct FakeCryptoModule {
    identity: ProviderIdentity,
    validation: ValidationState,
    advertised: CapabilitySet,
    state: Mutex<FakeState>,
}

impl FakeCryptoModule {
    /// A fixture with the given identity, no advertised capabilities, and no
    /// validation claim.
    pub fn new(identity: ProviderIdentity) -> Self {
        Self {
            identity,
            validation: ValidationState::NotValidated,
            advertised: CapabilitySet::empty(),
            state: Mutex::new(FakeState::default()),
        }
    }

    /// Advertise exactly `capabilities`.
    #[must_use]
    pub fn with_advertised_capabilities(mut self, capabilities: CapabilitySet) -> Self {
        self.advertised = capabilities;
        self
    }

    /// Declare the given validation state.
    #[must_use]
    pub fn with_validation_state(mut self, validation: ValidationState) -> Self {
        self.validation = validation;
        self
    }

    /// Make the self-test fail for `capabilities` from now on.
    pub fn fail_self_test_for(&self, capabilities: CapabilitySet) {
        self.state().self_test_failures = capabilities;
    }

    /// Make [`CryptoModule::self_test`] return
    /// [`SelfTestError::ModuleUnavailable`] from now on.
    pub fn make_self_test_unavailable(&self) {
        self.state().self_test_unavailable = true;
    }

    /// Withdraw current serviceability for `capabilities` (loss of readiness).
    pub fn withdraw_serviceability(&self, capabilities: CapabilitySet) {
        let mut state = self.state();
        state.unserviceable = state.unserviceable.union(capabilities);
    }

    /// Restore serviceability for `capabilities`.
    pub fn restore_serviceability(&self, capabilities: CapabilitySet) {
        let mut state = self.state();
        state.unserviceable = state.unserviceable.difference(capabilities);
    }

    fn state(&self) -> MutexGuard<'_, FakeState> {
        match self.state.lock() {
            Ok(guard) => guard,
            // A test that panicked while holding the lock left plain-data
            // state behind; recovering it is safe and keeps the fixture
            // panic-free.
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[async_trait]
impl CryptoModule for FakeCryptoModule {
    fn identity(&self) -> ProviderIdentity {
        self.identity.clone()
    }

    fn validation_state(&self) -> ValidationState {
        self.validation.clone()
    }

    fn advertised_capabilities(&self) -> CapabilitySet {
        self.advertised
    }

    async fn self_test(&self) -> Result<SelfTestOutcome, SelfTestError> {
        let (unavailable, failures) = {
            let state = self.state();
            (state.self_test_unavailable, state.self_test_failures)
        };
        if unavailable {
            return Err(SelfTestError::ModuleUnavailable);
        }
        let failed = self.advertised.intersection(failures);
        Ok(SelfTestOutcome::new(
            self.advertised.difference(failed),
            failed,
        ))
    }

    fn readiness(&self) -> ModuleReadiness {
        let unserviceable = self.state().unserviceable;
        ModuleReadiness::serviceable(self.advertised.difference(unserviceable))
    }
}
