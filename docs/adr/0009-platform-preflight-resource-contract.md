# ADR 0009: Platform Preflight Resource Contract

## Status

Accepted

## Date

2026-06-08

## Context

Carrier CNFs often depend on CPU isolation, NUMA locality, hugepages, NIC
capabilities, SR-IOV, AF_XDP/eBPF, CNI behavior, and pod-security exceptions.
These assumptions cannot remain tribal knowledge or comments in deployment
manifests.

## Decision

Production data-plane readiness is an explicit SDK contract:

- `opc-node-resources` models resource profiles and node capability reports.
- CPU manager, topology manager, isolated/reserved CPU sets, NUMA mappings,
  hugepage pools, NIC capabilities, and data-plane interfaces are validated.
- AF_XDP/eBPF artifacts require digest pinning, signer/evidence identity,
  program type, attach point, and allowed capability checks.
- Pod-security exceptions must be minimal and evidence-linked.
- Lab/dev fallback paths fail closed in production.
- Operator admission and config-apply paths consume the preflight report.

## Consequences

Production manifests must provide explicit resource profiles and node
capability evidence. If evidence is absent, stale, or incompatible, the SDK
policy blocks rollout instead of silently downgrading to lab behavior.

The Go reference operator projects this contract into CRD fields but does not
replace product-specific operator resource management.

## Evidence

- `crates/opc-node-resources/src/lib.rs`
- `crates/operator-lifecycle/src/admission.rs`
- `crates/operator-lifecycle/src/config_apply.rs`
- `operators/sdk-reference-operator/api/`

