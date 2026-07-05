# opc-route-steering

Safe Linux route and rule steering backend model for OpenPacketCore dataplane
adapters.

This crate provides:

- `RouteSteeringBackend`: an async trait for installing/removing destination
  routes and source/destination/firewall-mark rules, plus probing mutation
  readiness.
- `MockRouteSteeringBackend`: a deterministic in-memory test double that
  records operations and enforces `AlreadyExists`/`NotFound` semantics.
- `LinuxRouteSteeringBackend`: a safe production backend that encodes SDK route
  and rule requests into Linux rtnetlink messages through `opc-linux-route-sys`.
- `UnsupportedRouteSteeringBackend`: a backend that reports
  `UnsupportedPlatform` on all mutating operations for non-Linux or
  intentionally disabled builds.
- `RouteSteeringError`: an error enum with payload-free labels and raw errno
  access safe for logs and support bundles.
- `RouteSteeringProbe`: a capability probe covering route netlink reachability,
  effective `CAP_NET_ADMIN`, and mutation readiness.

Raw Linux socket work is intentionally kept in `opc-linux-route-sys`. This crate
does not implement route table allocation, per-session route policy, coexistence
with CNI routes, namespace management, product deployment defaults, or
traffic-readiness decisions.
