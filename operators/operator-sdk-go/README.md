# operator-sdk-go

Reusable Go packages for OpenPacketCore Kubernetes operators.

## Consumption contract

Downstream operators consume this module through the public module path:

```go
require openpacketcore.io/operator-sdk-go v0.2.0
```

Production product modules must not depend on local filesystem `replace`
directives for this SDK. The release path for this monorepo subdirectory is:

- publish a semver tag for this module using the Go subdirectory tag prefix,
  for example `operators/operator-sdk-go/v0.2.0`;
- serve `openpacketcore.io/operator-sdk-go` through the OpenPacketCore vanity
  import endpoint or module proxy so `go get openpacketcore.io/operator-sdk-go@vX.Y.Z`
  resolves to this subdirectory; and
- use local `go.work` workspaces only for unpublished SDK checkout testing.

The minimum supported toolchain is Go 1.26.4. The helper dependency line is
intentionally aligned with Kubernetes `v0.36.x` and controller-runtime
`v0.24.x`; downstream operators on older Go versions should either upgrade or
pin an older SDK module release that explicitly supports their toolchain.

## Status and boundary

The module provides product-neutral helper packages for conditions, the
Rust-policy CLI bridge, drain orchestration, rollout policy checks, workload
synthesis, CNI annotations, metrics, and test fakes.

The stable product-neutral package surface is:

- `bridge` for the Rust lifecycle CLI bridge;
- `conditions` for condition and phase state handling;
- `drain` for SDK-compatible admin drain helpers;
- `workload` for Kubernetes Deployment rendering;
- `cni` for Multus and SR-IOV annotation helpers;
- `gates` for readiness and endpoint-lineage checks;
- `rollout` for rollout policy and Deployment strategy helpers;
- `opmetrics` for operator Prometheus collectors; and
- `testing` for product operator unit-test fakes.

The Phase 4 packet-core helper additions are **experimental mechanism helpers**:

- named runtime-gate condition helpers;
- UDP/SCTP workload port helpers;
- Multus and SR-IOV attachment rendering helpers;
- rollout/drain helpers for SDK-compatible admin endpoints; and
- fake-client utilities for downstream operator unit tests.

They do not provide product CRDs, Helm values, RBAC policy, Multus network
attachment definitions, XFRM/IPsec privilege rendering, lawful-intercept mounts,
gNMI/config-push sequencing, or carrier-readiness claims. Product operators map
their own APIs and deployment policy onto these helpers.

## Verification

```bash
test -z "$(gofmt -l .)"
go vet ./...
go test ./...
./scripts/check-downstream-import.sh
```
