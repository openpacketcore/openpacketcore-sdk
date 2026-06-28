// Package operatorsdkgo provides reusable Go packages for building Kubernetes
// operators that manage 5G CNF (Cloud-Native Network Function) workloads using
// the OpenPacketCore SDK.
//
// The packages follow the SDK's Rust/Go split: Rust implements policy and
// protocol codecs; Go implements Kubernetes orchestration (conditions, drain,
// workload synthesis, metrics, and the bridge to the Rust lifecycle CLI).
// Packet-core helper additions for runtime gates, UDP/SCTP ports, Multus
// attachments, and drain integration are experimental mechanism helpers:
// product operators remain responsible for CRDs, Helm/RBAC, XFRM privileges,
// network attachment definitions, and readiness policy.
//
// Consumers typically depend on the sub-packages directly:
//   - conditions   — RFC 009 condition types and phase state machine
//   - bridge       — typed subprocess client for the Rust lifecycle CLI
//   - drain        — orchestrated drain against opc-runtime admin endpoints
//   - workload     — Deployment manifest synthesis from CR resource profiles
//   - cni          — Multus and SR-IOV attachment helpers
//   - gates        — Deployment, Pod readiness, and endpoint lineage helpers
//   - rollout      — RFC 009 rollout strategy helpers
//   - opmetrics    — Prometheus collectors and event recording
//   - testing      — fakes and fixtures for unit tests
package operatorsdkgo
