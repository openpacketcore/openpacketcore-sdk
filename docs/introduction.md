# Introduction

The OpenPacketCore SDK is a toolkit for building 5G Core Network Functions
(CNFs) that run on Kubernetes. It combines Rust-based policy engines with
Go-based Kubernetes orchestration to give operators both safety and
flexibility.

## What the SDK Provides

- **Rust crates** for protocol codecs (GTP-U, PFCP, NAS-5GS, NGAP v0, and the
  experimental `opc-proto-gtpv2c` S2b subset), session management,
  configuration consensus, alarms, and runtime chassis.
- **Go packages** (`operator-sdk-go`) for Kubernetes operators: conditions,
  bridge to Rust policy, drain orchestration, workload synthesis, and
  metrics.
- **Reference operator** (`sdk-reference-operator`) demonstrating end-to-end
  reconciliation of a network function custom resource.

## Getting Started

See [Quickstart](quickstart.md) for environment setup and your first
`SdkManagedNetworkFunction` deployment.

## Architecture

The SDK is documented through RFCs (high-level design) and ADRs
(decision records). Start with:

- [RFC 009 — Operator Lifecycle Upgrade](rfc/009-operator-lifecycle-upgrade.md)
- [ADR 0007 — Operator Lifecycle Rust Policy Core](adr/0007-operator-lifecycle-rust-policy-core.md)
