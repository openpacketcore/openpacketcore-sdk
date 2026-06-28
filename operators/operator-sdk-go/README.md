# operator-sdk-go

Reusable Go packages for OpenPacketCore Kubernetes operators.

## Status and boundary

The module provides product-neutral helper packages for conditions, the
Rust-policy CLI bridge, drain orchestration, rollout policy checks, workload
synthesis, CNI annotations, metrics, and test fakes.

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
```
