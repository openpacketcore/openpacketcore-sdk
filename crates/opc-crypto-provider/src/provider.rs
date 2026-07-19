//! The cryptographic-module provider trait: the seam itself.

use async_trait::async_trait;

use crate::capability::CapabilitySet;
use crate::identity::{ProviderIdentity, ValidationState};
use crate::selftest::{ModuleReadiness, SelfTestError, SelfTestOutcome};

/// A cryptographic module that reports identity, capabilities, self-test
/// outcome, and readiness.
///
/// This trait is deliberately evidence-only: it exposes no key handles and no
/// algorithm operations. Later slices bind TLS, IKEv2, entropy, and `opc-key`
/// custody operations to a module that a [`crate::ProviderPolicy`] has
/// admitted; nothing in this crate performs cryptography.
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
