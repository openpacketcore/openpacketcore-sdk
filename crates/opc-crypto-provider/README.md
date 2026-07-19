# opc-crypto-provider

Fail-closed capability reporting and policy admission boundary for
cryptographic modules.

## Purpose

`opc-crypto-provider` defines the seam through which security-critical
operations (TLS, IKEv2 PRF/integrity/encryption/signature/Diffie-Hellman,
entropy, zeroization, sealed key storage) can later be routed to exactly one
explicitly selected cryptographic module, and through which a deployment can
prove at runtime which module answered. It implements **no cryptographic
algorithms** and integrates with no other SDK crate; it is the capability
model, evidence, and admission policy only.

The design is fail-closed throughout: an unknown or unreported capability
never reads as available, a failed or unrun self-test and any loss of
readiness withdraw the capability from the effective set, and a policy that
requires a capability the selected module cannot provide rejects instead of
falling back to another code path.

## API Shape

- `CryptoCapability` / `CapabilitySet` — the security-critical operation
  families and a fail-closed set over them (default: empty).
- `ProviderIdentity` (`ProviderName`, `ProviderVersion`) — bounded, log-safe
  module identity bound into every report.
- `ValidationState` — the module's **self-declared** validation claim.
  Defaults to `NotValidated`; the SDK never verifies or certifies a claim.
- `SelfTestOutcome` / `SelfTestEvidence` / `ModuleReadiness` — per-capability
  self-test and readiness evidence with capability withdrawal.
- `CapabilityReport` / `probe_capability_report` — bounded, redaction-safe
  evidence for readiness endpoints and release artifacts; carries no key
  material by construction.
- `ProviderPolicy` / `PolicyAdmission` / `PolicyError` — fail-closed
  admission; `PolicyAdmission` is only constructible through a successful
  `ProviderPolicy::admit`.
- `CryptoModule` — the async provider trait: identity, capabilities,
  self-test, readiness.
- `testkit::FakeCryptoModule` (feature `testkit`) — configurable fixture that
  can drop capabilities, fail its self-test, or lose readiness so tests can
  prove the fail-closed behavior.

## Non-goals

This crate makes no FIPS 140 or other certification claim and does not imply
the SDK certifies a deployment; it records a module's self-declared name,
version, and validation state as evidence only. It selects no vendor, module,
certification boundary, or deployment algorithm policy, and the non-validated
path is the ergonomic default.
