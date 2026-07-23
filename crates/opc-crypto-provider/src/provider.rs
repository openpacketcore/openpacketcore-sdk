//! The cryptographic-module provider trait: the seam itself.

use async_trait::async_trait;

use crate::capability::CapabilitySet;
use crate::identity::{ProviderIdentity, ValidationState};
use crate::ops::IkeCryptoOperations;
use crate::selftest::{ModuleReadiness, SelfTestError, SelfTestOutcome};

/// A cryptographic module that reports identity, capabilities, self-test
/// outcome, and readiness.
///
/// This trait is deliberately evidence-only: it exposes no key handles and no
/// algorithm operations. [`IkeCryptoModule`] composes this evidence surface
/// with the IKEv2 operation traits so one exact object can be admitted and
/// execute IKEv2 operations. `opc-key` defines its own downstream composite
/// evidence/remote-seal binding; TLS binding remains outside this crate.
/// Nothing in this crate itself performs cryptography.
///
/// The name avoids `CryptoProvider`, which already means the IKEv2
/// protected-payload opener in `opc-proto-ikev2`; consumers of both traits
/// would otherwise collide on imports.
///
/// The trait is async and object-safe (`dyn CryptoModule`) because
/// [`Self::self_test`] may reach out to an external module such as an HSM.
/// The remaining methods are synchronous snapshots and must be cheap and
/// non-blocking: readiness endpoints poll them frequently.
#[async_trait]
pub trait CryptoModule: Send + Sync {
    /// Stable identity (name and version) of the module answering every other
    /// method on this instance.
    fn identity(&self) -> ProviderIdentity;

    /// The validation status the module declares for itself.
    ///
    /// The declaration is recorded as evidence and is never verified by the
    /// SDK. Ordinary modules return [`ValidationState::NotValidated`].
    fn validation_state(&self) -> ValidationState;

    /// Capabilities the module advertises when fully self-tested and ready.
    ///
    /// Advertisement alone makes nothing available: the effective set also
    /// requires a passed self-test and current readiness (see
    /// [`crate::CapabilityReport::effective_capabilities`]).
    fn advertised_capabilities(&self) -> CapabilitySet;

    /// Run the module's self-test and report the per-capability outcome.
    ///
    /// An `Err` means the self-test could not run at all; callers must treat
    /// it exactly like an outcome that passed nothing (fail closed).
    async fn self_test(&self) -> Result<SelfTestOutcome, SelfTestError>;

    /// Which capabilities the module can service right now.
    ///
    /// A capability missing from the serviceable set is withdrawn from the
    /// effective set even while it remains advertised.
    fn readiness(&self) -> ModuleReadiness;
}

/// One cryptographic module that supplies both IKEv2 evidence and operations.
///
/// A process-level IKEv2 admission stores this composite trait object rather
/// than unrelated evidence and operation objects. This structurally prevents
/// a policy admission for one module from authorizing operations on another.
pub trait IkeCryptoModule: CryptoModule + IkeCryptoOperations {}

impl<T> IkeCryptoModule for T where T: CryptoModule + IkeCryptoOperations {}

/// Compile-time proof that the composite module trait remains object-safe.
#[allow(dead_code)]
fn assert_ike_crypto_module_is_object_safe(_module: &dyn IkeCryptoModule) {}
