# Opc Testbed

Scenario DSL, virtual time, assertions, fixture provenance, and simulator framework.

## Status

**Core framework: Production-ready. EPC/ePDG simulator skeletons: experimental.**

## Reference

[`RFC 012`](../../docs/rfc/012-testbed-simulator-framework.md) and the
[EPC/ePDG simulator design](../../docs/design/epc-epdg-testbed-simulators.md).

## Simulator skeletons

- `simulators::fake`, `amf`, `smf`, and `upf` provide existing in-process peer
  mechanics for scenario runner tests.
- `simulators::epc::PgwS2bSimulator` accepts SDK-decoded S2b views, with
  `opc-proto-gtpv2c` owning byte parsing and fixture conformance. RFC 012
  fidelity = `stateful-mock` (experimental); not procedure-faithful, not
  conformance, and not a production PGW/ePDG control plane.
- `simulators::epc::DiameterPeerSimulator` accepts decoded Diameter metadata
  from the experimental `opc-proto-diameter` crate or compatible product
  adapters; it intentionally carries no local Diameter parser. RFC 012 fidelity
  = `stateful-mock` (experimental); not procedure-faithful, not conformance,
  and not a production AAA/HSS/CDF peer.
- `tests/epdg_sdk_composition.rs` composes the current SDK-owned ePDG building
  blocks in one regression path: S2b fixture decode, SWm DER build/parse,
  Diameter peer metadata recording, IKEv2 Child SA to XFRM request mapping,
  mock XFRM composite install, and packet-core evidence redaction validation.
  This is a composition guard, not downstream attach orchestration or carrier
  acceptance evidence.

## Quick start

```rust,no_run
use opc_testbed::...;

fn main() {
    // See the crate documentation for full API usage.
}
```

## License

This crate is licensed under the [Apache License, Version 2.0](../../LICENSE).
