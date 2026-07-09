# opc-route-steering

## Purpose

`opc-route-steering` is the safe Rust control surface for Linux route and rule
steering used by OpenPacketCore dataplane adapters. It models destination
routes, source/destination/firewall-mark rules, backend capability probes, mock
behavior, Linux rtnetlink mutation, and redaction-safe errors.

The crate does not choose route tables, rule priorities, CNI coexistence
policy, namespace placement, or product traffic-readiness policy.

## API Shape

- `RouteSteeringBackend`: async port for `install_route`, `remove_route`,
  `install_rule`, `remove_rule`, and `probe`.
- `LinuxRouteSteeringBackend`: safe adapter over rtnetlink through
  `opc-linux-route-sys`.
- `MockRouteSteeringBackend`: deterministic in-memory backend with operation
  capture and failure injection.
- `UnsupportedRouteSteeringBackend`: trait-compatible unsupported backend.
- Model exports: `IpPrefix`, `FirewallMark`, `RouteRequest`, `RuleRequest`,
  `RouteSteeringProbe`, and `RouteSteeringBackendKind`.
- `RouteSteeringError` exposes stable labels and raw OS errno access without
  leaking kernel messages into formatted output.

## Usage

```rust,no_run
use std::net::{IpAddr, Ipv4Addr};

use opc_route_steering::{
    IpPrefix, MockRouteSteeringBackend, RouteRequest, RouteSteeringBackend,
    RuleRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = MockRouteSteeringBackend::new();
    let prefix = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 23, 0, 0)), 24);
    let route = RouteRequest {
        destination: prefix,
        oif_ifindex: 42,
        table: 100,
        priority: Some(10),
    };
    let rule = RuleRequest {
        source: Some(prefix),
        destination: None,
        fwmark: None,
        table: 100,
        priority: 1000,
    };

    backend.install_route(route.clone()).await?;
    backend.install_rule(rule.clone()).await?;
    backend.remove_rule(rule).await?;
    backend.remove_route(route).await?;
    Ok(())
}
```

## Relationships

- `opc-linux-route-sys` owns the raw rtnetlink socket and UAPI constants.
- GTP-U and XFRM crates produce dataplane state that product code may pair with
  route steering, but this crate does not compose those policies itself.

## Status And Limits

- Unpublished workspace crate (`publish = false`).
- Safe Rust only (`#![forbid(unsafe_code)]`).
- Linux mutation requires rtnetlink access and effective `CAP_NET_ADMIN`.
- Validation rejects invalid prefixes, ifindexes, and table values before
  encoding netlink messages.

## Roadmap

- Keep table/priority allocation in product or orchestration layers.
- Add new rule selectors only when the model and Linux encoder can reject
  unsupported combinations clearly.
- Add privileged integration coverage before relying on new kernel behavior.

## Verification

```sh
cargo test -p opc-route-steering
```
