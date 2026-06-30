# Opc Runtime

CNF runtime chassis: process startup phases, task supervision, health probes, and graceful SIGTERM drains.

## Status

**Production-ready**

## Reference

[RFC](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/docs/rfc/008-cnf-runtime-chassis.md)

## Quick start

```rust,no_run
use opc_runtime::...;

fn main() {
    // See the crate documentation for full API usage.
}
```

## Named health gates

Products can attach their own readiness/degradation policy to the generic
`HealthGateSet` without hard-coding product names into the SDK. Use the
`known_gates` constants or define your own gate names, set each gate's
`GateImpact`, and let `HealthModel` aggregate them into a `Readiness` verdict.

```rust
use opc_runtime::{
    known_gates, GateImpact, GateStatus, HealthGate, HealthGateSet, HealthModel,
};

fn configure_readiness(model: &mut HealthModel) {
    // Map product-specific checks onto generic SDK gates.
    let mut gates = HealthGateSet::new();
    gates.insert(HealthGate::new(known_gates::CONFIG, GateImpact::BlocksReadiness)
        .with_status(GateStatus::Passing));
    gates.insert(HealthGate::new(known_gates::XFRM, GateImpact::BlocksReadiness)
        .with_status(GateStatus::Passing));
    gates.insert(HealthGate::new(known_gates::CHARGING_PEER, GateImpact::DegradesReadiness)
        .with_status(GateStatus::Failing)
        .with_message("no reachable CGF"));

    // Assign the gate set to the health model; readiness is recomputed.
    for gate in gates.iter().cloned() {
        model.set_gate(gate);
    }
}
```

Gate semantics are fail-closed: an unknown status is treated as non-passing.
`Informational` gates are reported in detailed health JSON but do not affect
readiness. When no gates are registered, cheap `/readyz` probe output is
unchanged.

## UDP destination metadata

`bind_udp_socket_with_destination_metadata` returns a Tokio UDP listener wrapper
whose receive result includes payload length, source endpoint, and local
destination endpoint metadata. Linux listeners use packet-info ancillary data
when available; other platforms and non-packet-info paths fall back to concrete
`local_addr()` evidence and report an unavailable status for wildcard binds.

## License

This crate is licensed under the [Apache License, Version 2.0](../../LICENSE).
