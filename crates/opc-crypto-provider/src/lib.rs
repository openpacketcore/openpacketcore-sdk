#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! Fail-closed capability reporting and policy admission for cryptographic
//! modules.
//!
//! This crate defines the seam through which security-critical operations
//! (TLS, IKEv2 PRF/integrity/encryption/signature/Diffie-Hellman, entropy,
//! zeroization, sealed key storage) can later be routed to exactly one
//! explicitly selected cryptographic module. It contains **no cryptographic
//! algorithm implementations** and binds to no existing SDK crate; it defines
//! only the capability model, evidence types, and admission policy that make
//! silent fallback to an unapproved code path impossible:
//!
//! - [`CryptoCapability`] and [`CapabilitySet`] model what a module advertises.
//!   The set is fail-closed: an unknown or unreported capability never reads
//!   as available, and the default set is empty.
//! - [`ProviderIdentity`] binds a bounded, log-safe module name and version to
//!   every report so a consumer can tell *which* module answered.
//! - [`ValidationState`] records whether a module *declares* validated status.
//!   The default is [`ValidationState::NotValidated`]; ordinary deployments
//!   compose non-validated modules without claiming anything.
//! - [`SelfTestOutcome`], [`SelfTestEvidence`], and [`ModuleReadiness`]
//!   withdraw a capability when its self-test fails, when the self-test could
//!   not run, or when readiness is lost — the capability is then absent from
//!   the effective set instead of staying advertised.
//! - [`CapabilityReport`] is bounded, redaction-safe evidence binding
//!   capabilities to identity, version, and validation state. It can never
//!   carry key material because no type in this crate holds key material.
//! - [`ProviderPolicy`] admits a module only when every required capability is
//!   effective. Rejection is typed and happens before any operation could be
//!   admitted: [`PolicyAdmission`] is only constructible through
//!   [`ProviderPolicy::admit`], and there is no fallback path.
//! - [`CryptoModule`] is the provider trait itself: identity, capabilities,
//!   self-test, readiness. Later slices bind runtime health gates, IKEv2, TLS,
//!   and `opc-key` custody to an admitted module; this crate deliberately
//!   exposes no key or algorithm operations on it.
//! - The [`ops`] module defines the synchronous, object-safe IKE
//!   **operation traits** ([`IkePrfOperations`], [`IkeIntegrityOperations`],
//!   [`IkeEncryptionOperations`], [`IkeDiffieHellmanOperations`],
//!   [`IkeSignatureOperations`]) grouped along the capability taxonomy.
//!   These are contracts only — this crate still implements no cryptography,
//!   and secret-bearing state stays behind opaque handles
//!   ([`IkeDhKeyPair`], [`IkeSigningKey`]) or zeroizing buffers.
//!
//! # No certification claim
//!
//! Validation status in this crate is a module's **self-declared** claim,
//! recorded verbatim as evidence. The SDK never verifies such a claim, never
//! certifies a module or a deployment, and never implies that a declared
//! status is externally certified. Nothing here selects a vendor, module,
//! certification boundary, or algorithm policy for a deployment.

pub mod capability;
pub mod identity;
pub mod ops;
pub mod policy;
pub mod provider;
pub mod report;
pub mod selftest;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

pub use capability::{CapabilitySet, CryptoCapability};
pub use identity::{
    ProviderIdentity, ProviderLabelError, ProviderName, ProviderVersion, ValidationReference,
    ValidationState,
};
pub use ops::{
    CryptoOperationError, CryptoOperationErrorCode, IkeAeadAlgorithm, IkeCbcAlgorithm, IkeDhGroup,
    IkeDhKeyPair, IkeDiffieHellmanOperations, IkeEncryptionOperations, IkeIntegrityAlgorithm,
    IkeIntegrityOperations, IkePrfAlgorithm, IkePrfOperations, IkeSignatureAlgorithm,
    IkeSignatureOperations, IkeSigningKey,
};
pub use policy::{PolicyAdmission, PolicyError, ProviderPolicy};
pub use provider::CryptoModule;
pub use report::{probe_capability_report, CapabilityReport};
pub use selftest::{ModuleReadiness, SelfTestError, SelfTestEvidence, SelfTestOutcome};
