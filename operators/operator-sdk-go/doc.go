// Package operatorsdkgo provides reusable Go packages for building Kubernetes
// operators that manage 5G CNF (Cloud-Native Network Function) workloads using
// the OpenPacketCore SDK.
//
// The packages follow the SDK's Rust/Go split: Rust implements policy and
// protocol codecs; Go implements Kubernetes orchestration (conditions, drain,
// workload synthesis, metrics, and the bridge to the Rust lifecycle CLI).
//
// Consumers typically depend on the sub-packages directly:
//   - conditions   — RFC 009 condition types and phase state machine
//   - bridge       — typed subprocess client for the Rust lifecycle CLI
//   - drain        — orchestrated drain against opc-runtime admin endpoints
//   - workload     — Deployment manifest synthesis from CR resource profiles
//   - opmetrics    — Prometheus collectors and event recording
//   - testing      — fakes and fixtures for unit tests
package operatorsdkgo
