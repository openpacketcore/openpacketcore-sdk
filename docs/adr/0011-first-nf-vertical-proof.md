# ADR 0011: First NF Vertical Proof

## Status

Accepted

## Date

2026-06-08

## Context

The SDK needed proof that its seams compose in a real NF-shaped control-plane
slice. Toy examples can validate local APIs, but they do not prove that runtime,
config, session, identity, KMS, NACM, alarms, metrics, and HA recovery work
together.

## Decision

`opc-amf-lite` is the first NF vertical integration proof.

It demonstrates:

- Runtime startup and supervised workers.
- Secure ConfigBus integration.
- Consensus-backed configuration persistence.
- Quorum session storage with read-repair behavior.
- KMS-backed encryption paths.
- NACM authorization and audit.
- Alarm and metrics integration.
- HA recovery and failure validation.

`opc-amf-lite` is not a product AMF. It is a reusable SDK proof slice that
downstream CNFs can study when wiring their own production crates.

## Consequences

The SDK can claim that its core seams compose into an NF-shaped control-plane
vertical. It cannot claim complete AMF/SMF/UPF protocol coverage from this
slice.

Future NF crates should follow the integration pattern but own their
procedure-specific logic, protocol fidelity, and product tests.

## Evidence

- `crates/opc-amf-lite/`
- `crates/opc-amf-lite/README.md`
- `docs/implementation-status.md`
- `docs/operator-readiness.md`

