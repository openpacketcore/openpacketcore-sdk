# opc-route-steering

## Purpose

`opc-route-steering` is the safe Rust control surface for Linux route and rule
steering used by OpenPacketCore dataplane adapters. It models destination
routes, source/destination/firewall-mark rules, backend capability probes,
conflict-safe resident-state convergence, authoritative owned collection
reconciliation, mock behavior, Linux rtnetlink mutation/readback, and
redaction-safe errors.

The crate does not choose route tables, rule priorities, CNI coexistence
policy, namespace placement, or product traffic-readiness policy.

## API Shape

- `RouteSteeringBackend`: async port for legacy exclusive mutation, typed
  `read_route`/`read_rule`, single-object convergence, explicit
  `remove_converged_route`/`remove_converged_rule`, cancellation-safe paired
  route/rule convergence, bounded `snapshot_owned_route_rules` and
  `reconcile_owned_route_rules`, typed `capabilities`, and runtime `probe`.
- `LinuxRouteSteeringBackend`: safe adapter over rtnetlink through
  `opc-linux-route-sys`.
- `MockRouteSteeringBackend`: deterministic in-memory backend with Linux-style
  bounded multimap collisions, legacy mutation/probe operation capture,
  separate typed read observations, owned/foreign fixture seeding, and
  targeted failure injection.
- `UnsupportedRouteSteeringBackend`: trait-compatible unsupported backend.
- Model exports include `RouteReadback`, `RuleReadback`, typed conflict and
  mismatch evidence, per-object convergence outcomes, and
  `RouteRuleConvergenceOutcome`. The additive `OwnedRouteRuleScope`,
  `OwnedRouteRuleSet`, `OwnedRouteRuleSnapshot`, and
  `OwnedRouteRuleReconcileOutcome` types model one complete exclusive-writer
  collection. `RouteSteeringCapabilities` prevents callers from treating
  legacy mutation support as conflict-safe singleton or collection
  convergence support.
- `RouteSteeringError` exposes stable labels and raw OS errno access without
  leaking kernel messages into formatted output.

## Usage

```rust,no_run
use std::net::{IpAddr, Ipv4Addr};

use opc_route_steering::{
    IpPrefix, MockRouteSteeringBackend, RouteConvergenceOutcome, RouteRequest,
    RouteSteeringBackend, RouteRuleRollback, RuleConvergenceOutcome, RuleRequest,
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

    let outcome = backend
        .converge_route_and_rule(route.clone(), rule.clone())
        .await?;
    assert_eq!(outcome.route, RouteConvergenceOutcome::Installed);
    assert_eq!(outcome.rule, RuleConvergenceOutcome::Installed);
    assert_eq!(outcome.rollback, RouteRuleRollback::NotNeeded);

    // A retry proves exact resident equality rather than trusting EEXIST.
    let retry = backend
        .converge_route_and_rule(route.clone(), rule.clone())
        .await?;
    assert_eq!(retry.route, RouteConvergenceOutcome::ExactAlreadyPresent);
    assert_eq!(retry.rule, RuleConvergenceOutcome::ExactAlreadyPresent);

    backend.remove_converged_rule(rule).await?;
    backend.remove_converged_route(route).await?;
    Ok(())
}
```

For a complete writer-owned set, use the collection API. This is also the API
for provably disjoint source rules that intentionally share one family and
priority:

```rust,no_run
use std::net::{IpAddr, Ipv4Addr};

use opc_route_steering::{
    IpPrefix, MockRouteSteeringBackend, OwnedRouteRuleScope, OwnedRouteRuleSet,
    RouteSteeringBackend, RouteSteeringIpFamily, RuleRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = MockRouteSteeringBackend::new();
    let scope = OwnedRouteRuleScope::new(
        RouteSteeringIpFamily::Ipv4,
        100,      // route and rule table
        42,       // route output interface
        Some(10), // canonical route metric
        1000,     // exclusively owned rule priority
    )?;
    let first = RuleRequest {
        source: Some(IpPrefix::new(
            IpAddr::V4(Ipv4Addr::new(10, 23, 0, 0)),
            25,
        )),
        destination: None,
        fwmark: None,
        table: 100,
        priority: 1000,
    };
    let second = RuleRequest {
        source: Some(IpPrefix::new(
            IpAddr::V4(Ipv4Addr::new(10, 23, 0, 128)),
            25,
        )),
        destination: None,
        fwmark: None,
        table: 100,
        priority: 1000,
    };

    let desired = OwnedRouteRuleSet::new(scope, Vec::new(), vec![first, second.clone()])?;
    let applied = backend.reconcile_owned_route_rules(desired.clone()).await?;
    assert_eq!(applied.snapshot.rules(), desired.rules());

    // Exact retry performs no adoption based only on EEXIST.
    let retried = backend.reconcile_owned_route_rules(desired).await?;
    assert_eq!(retried.retained_rules, 2);

    // Reconcile the complete set without the first rule; its sibling remains.
    let only_second = OwnedRouteRuleSet::new(scope, Vec::new(), vec![second])?;
    let reduced = backend.reconcile_owned_route_rules(only_second).await?;
    assert_eq!(reduced.snapshot.rules().len(), 1);
    assert_eq!(reduced.removed_rules, 1);

    // An empty authoritative set garbage-collects representable owned orphans.
    let empty = OwnedRouteRuleSet::new(scope, Vec::new(), Vec::new())?;
    backend.reconcile_owned_route_rules(empty).await?;
    Ok(())
}
```

## Convergence Contract

- The built-in Linux and mock route collision key is the address family,
  effective destination network prefix, and routing table. Route convergence,
  readback, and mock resident state clear IPv4/IPv6 host bits before comparison,
  matching the Linux FIB. Equality within that key also compares the output
  interface, optional metric, fixed unicast kernel semantics, and namespace
  ownership protocol emitted by this crate. IPv4 `None`/zero metrics
  canonicalize to an absent attribute; IPv6 `None`/zero canonicalize to the
  kernel's effective metric `1024`. The public mismatch evidence retains a
  table field for external backends that use a broader collision key. This does
  not canonicalize rule selectors. Legacy Linux route install/remove still
  emits the caller-supplied destination bytes, and legacy mock mutation
  operations record the exact caller request.
- A rule's logical collision key is its address family and priority. Equality
  compares source, destination, firewall mark and mask, table, priority, and
  the fixed table-lookup semantics and namespace ownership protocol emitted by
  this crate. Convergence-owned Linux route `rtm_protocol` and rule
  `FRA_PROTOCOL` use `LINUX_ROUTE_STEERING_PROTOCOL` (`242`). Missing, legacy,
  or other protocol values are foreign conflicts, never exact resident state.
- A rule containing only a firewall mark uses Linux's IPv4 rule family (the
  same default used by `ip rule`). Source- or destination-qualified rules
  derive their family from that prefix. Legacy mutation and readback preserve
  IPv4/IPv6 `/0` family selectors and a zero firewall-mark value. Conflict-safe
  convergence and exact owned removal reject `/0` and mark zero with a typed
  `InvalidConfig`; Linux treats those values as delete wildcards. Mark masks
  remain nonzero for both APIs.
- Bounded readback returns `ExactPresent` only for one fully representable
  object. A modeled difference returns `Conflict`; malformed, incomplete,
  oversized, unsupported, or unmodeled colliding state returns
  `Indeterminate`. `AlreadyExists` alone is never idempotent success.
- Convergence reads before mutation and verifies again after a successful
  exclusive create. A collision introduced across that race is never reported
  as installed; the object owned by the call is removed and the typed outcome
  records conflict/indeterminate-after-rollback.
- `remove_converged_route`/`remove_converged_rule` require exactly one owned
  exact candidate immediately before deletion and verify the broad key is
  absent afterward. Multiplicity, foreign protocol state, semantic route cache
  expiry/error, or unfamiliar attributes fail closed without issuing a normal
  delete. The original `remove_route`/`remove_rule` retain their legacy
  best-effort semantics and are not ownership-safe APIs.
- Paired convergence handles the route first. If the rule cannot converge, it
  removes only objects installed by the same call and only after the exact
  ownership check succeeds. Post-install races can report owned rule, route,
  or combined rollback; ambiguous rollback returns a typed failure.
- Singleton rule readback deliberately treats multiple candidates at one
  family/priority collision key as ambiguous. The collection API is the
  additive path for siblings at that key: construction permits more than one
  rule only when every sibling is source-only, non-wildcard, and its prefix is
  provably disjoint from every other sibling. Exact duplicates, overlapping
  prefixes, destination or firewall-mark siblings, and wildcard selectors are
  rejected before mutation.
- `OwnedRouteRuleScope` makes collection authority explicit: one address
  family, route/rule table, route output interface and canonical metric, and
  rule priority. `OwnedRouteRuleSet` is the complete desired state for that
  scope; `OwnedRouteRuleSnapshot` is a complete bounded enumeration of its
  representable protocol-`242` state. Ownership-tagged objects that cannot be
  modeled and duplicate or ambiguous owned state fail the snapshot instead of
  being omitted. Foreign state is never included or adopted; a foreign object
  colliding with an owned or desired target blocks reconciliation before
  deletion.
- Collection reconciliation is one serialized authoritative operation, not a
  kernel-atomic transaction. It validates the complete bounded snapshot and
  desired set before deletion, installs and verifies all missing desired
  objects first, removes orphan rules before orphan routes, then proves a final
  exact snapshot. Desired and final collections admit at most `50,000` routes
  and `50,000` rules each. The install-before-delete old∪new intermediate has
  a separate ceiling of `100,000` routes and `100,000` rules, so replacing a
  full final collection does not require unsafe deletion first. The initial
  recovery snapshot of a reconcile also accepts this transient ceiling, which
  lets a restarted writer collect an interrupted old∪new residual above the
  final bound. Public snapshots and the successful final snapshot retain the
  lower ceiling. A partial or uncertain operation returns typed
  `ReconcileIncomplete` phase/count evidence, including typed rollback-failure
  evidence when attempted cleanup is itself incomplete; it never uses an
  incomplete, over-limit, or changing dump to prove absence. Retry the complete
  desired set to converge from authoritative readback.
- Collection ownership survives loss of process-local attempt history because
  restart cleanup enumerates the explicit protocol-`242` scope. The product
  must durably reconstruct the complete desired set before reconciling; an
  empty desired set intentionally garbage-collects every representable owned
  object in that scope. The backend does not persist product intent.
- Every Linux read, mutation, and convergence operation acquires one
  clone-shared lock inside its blocking worker. A pair holds the lock once
  through post-install verification and rollback. If its async waiter is
  cancelled, the worker retains the lock and completes; the caller must retry
  to obtain the resulting typed state.
- A Linux mutation is counted as acknowledged only after exactly one matching
  zero-error `NLMSG_ERROR` ACK. Empty or `NOOP`-only datagrams do not complete
  the operation; `DONE`, arbitrary payload messages, duplicate ACKs, timeout,
  and malformed replies fail closed. A lost or structurally uncertain ACK is
  not evidence that the mutation was unapplied.
- Linux rule convergence first checks non-mutating `FRA_PROTOCOL` capability
  evidence. Plain upstream kernels older than 4.17 fail before desired-state
  mutation. An older vendor/custom version remains `Unknown` because it may
  contain a backport. Every allowed create is still verified by readback. If a
  kernel ACKs but silently discards the marker, the exact rule created by that
  serialized attempt is deleted immediately, absence is verified, and
  `LinuxRuleProtocolCapability::UnsupportedByReadback` is cached. No global or
  collision-prone probe rule is installed. A validated IPv4 tagged create
  rejected with an unsupported-attribute kernel error is cached separately as
  `UnsupportedByKernelRejection` only before positive tagged readback; no
  cleanup is needed because creation failed. `Confirmed` evidence is monotonic:
  a later generic create failure remains its original operational error and does
  not disable subsequent attempts. IPv6-family rejection is likewise preserved
  as an operational/family error rather than treated as global marker evidence.
- `RouteSteeringCapabilities::owned_route_rule_collection` means that the
  complete adapter contract is implemented and a fail-closed, self-verifying
  attempt is currently permitted. It is not `FRA_PROTOCOL` attestation. On a
  fresh namespace, `LinuxRuleProtocolCapability::Unknown` or
  `ExpectedByKernelVersion` deliberately permits bootstrap: every created rule
  is read back before success, and a rejected or discarded marker disables
  later attempts. Only `LinuxRuleProtocolCapability::Confirmed` is positive
  marker-retention evidence. Consumers must not require `Confirmed` before the
  first reconcile, because an empty namespace has no resident tag to observe.
- Existing third-party trait implementations compile unchanged. Their default
  readback, convergence, exact owned removal, and paired convergence are
  fail-closed `Unsupported`/`Indeterminate` until explicitly implemented. The
  collection defaults also fail closed, and
  `RouteSteeringCapabilities::owned_route_rule_collection` remains false until
  an adapter explicitly implements the full snapshot/reconciliation contract.

The ownership protocol is a namespace-local reservation, not authentication.
Constructing and reconciling an `OwnedRouteRuleScope` asserts that the caller
has exclusive writer authority for that scope and no other writer can
impersonate protocol `242`. Within that boundary, the marker is eligible owned
state. Outside it, the backend cannot authenticate marker provenance: do not
invoke collection garbage collection, and treat the state operationally as
conflicting or indeterminate. Clones of one backend are serialized. Separate
backend instances, direct `ip`/netlink writers, overlapping family/priority
scopes, table/priority allocation, and replacement of intentionally stale
foreign objects require external coordination. The API does not automatically
replace conflicts and never treats `EEXIST` as proof of ownership.

## Legacy Compatibility And Migration

The original `install_route` continues to emit Linux `RTPROT_STATIC` (`4`), and
the original `install_rule` remains untagged. Their existing `/0`, mark-zero,
and best-effort removal behavior is preserved. These methods are intentionally
separate from the new convergence authority: an object created by a legacy SDK
release or direct `ip` command is reported as a foreign conflict even when all
modeled request fields match. The SDK never silently adopts or deletes it.

Before switching a namespace to convergence, the operator/product must remove
known legacy-owned state under its existing writer serialization, then call
`converge_*`. If provenance is not independently known, leave the object in
place and resolve the typed conflict operationally. `remove_converged_*` must
not be used as an adoption mechanism.

Before switching to collection reconciliation, allocate a non-overlapping
`OwnedRouteRuleScope`, establish one exclusive writer for that scope, and make
the complete desired set recoverable across process restart. The first
authoritative reconcile can then enumerate and remove stale protocol-`242`
objects from an interrupted prior process without relying on lost in-memory
ownership. Legacy static/untagged objects and foreign collisions remain
untouched and must be resolved by the authority that can prove their
provenance.

Routing policy is also explicit: BGP/export filters that match Linux
`protocol static` continue to see legacy installs, while convergence-owned
routes use protocol `242`. Deployments that intend to redistribute those routes
must add an explicit policy for `242`; the SDK does not alter BGP policy or
pretend protocol `242` is `static`.

## Relationships

- `opc-linux-route-sys` owns the raw rtnetlink socket and UAPI constants.
- GTP-U and XFRM crates produce dataplane state that product code may pair with
  route steering, but this crate does not compose those policies itself.

## Status And Limits

- Unpublished workspace crate (`publish = false`).
- Safe Rust only (`#![forbid(unsafe_code)]`).
- Linux mutation requires rtnetlink access and effective `CAP_NET_ADMIN`.
- Validation rejects invalid prefixes, zero rule mark masks, ifindexes, and
  table values for every API. Exact convergence/removal additionally rejects
  optional `/0` rule selectors and a zero rule mark value before encoding a
  netlink mutation; legacy mutation/readback retain those request shapes.
- Linux readback uses bounded `RTM_GETROUTE`/`RTM_GETRULE` multipart dumps.
  `LinuxRouteSteeringBackendConfig` bounds receive attempts and each datagram;
  `LinuxRouteReadbackLimits` bounds aggregate bytes, datagrams, and decoded
  messages.
- `OwnedRouteRuleSet` and final/public `OwnedRouteRuleSnapshot` values impose
  separate hard bounds of `50,000` routes and `50,000` rules. Reconciliation
  can represent the install-before-delete old∪new intermediate up to
  `100,000` routes and `100,000` rules. `LinuxOwnedRouteRuleCollectionLimits`
  can apply tighter final, transient, and per-dump byte/datagram/message bounds
  without changing the legacy per-key limits. The default hard envelope for
  each complete Linux route or rule dump is `65,535` datagrams, `131,072`
  decoded messages, and `64 MiB` of aggregate reply bytes. Each collection
  snapshot uses one complete route dump and one complete rule dump, not one
  full dump per desired member, and fails closed rather than return a partial
  collection.
  Under the default collection limits, synthetic Linux tests classify
  `50,000` owned routes plus `50,000` source-disjoint, same-priority owned rules
  returned by exactly those two `AF_UNSPEC` dump requests, and separately pass
  `50,000` multipart messages through the production byte/datagram/message
  accounting parser. This substantiates bounded snapshot enumeration capacity
  only, not `50,000` kernel installs/deletes, end-to-end reconciliation
  throughput, or kernel-atomic mutation. Collection capability means the full
  snapshot/reconciliation contract is implemented and may be attempted with
  fail-closed verification; it is not marker-retention attestation and does
  not change those evidence limits.
- `RTA_CACHEINFO` volatile counters are ignored only when signed expiry and
  error fields are zero; either semantic field being nonzero is indeterminate.
  Kernels reporting unsupported address/protocol families or unsupported
  operations map to a typed unsupported result.

## Roadmap

- Keep table/priority allocation in product or orchestration layers.
- Add new rule selectors only when the model and Linux encoder can reject
  unsupported combinations clearly.
- Keep privileged kernel-version qualification in the consuming release's
  evidence; unsupported or unfamiliar reply shapes remain fail closed.

## Verification

```sh
cargo test -p opc-route-steering

# Linux: exercise real IPv4/IPv6 route/rule mutation in an isolated namespace.
unshare -Urn sh -c 'ip link set lo up; cargo test -p opc-route-steering \
  --test live_readback_probe -- --ignored'
```
