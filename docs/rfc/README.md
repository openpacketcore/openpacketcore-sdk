# OpenPacketCore SDK RFC Index

This directory contains the foundational RFCs for the OpenPacketCore SDK and
CNF architecture. These documents are intended to be implementation inputs for
engineers.

## Foundation Set

| RFC | Title | Primary Scope |
| :--- | :--- | :--- |
| [001](001-management-substrate.md) | Transactional Management Substrate | Config commits, persistence, recovery, NACM boundary |
| [002](002-yang-projection.md) | YANG-to-Rust Projection | Codegen, RFC 7951, validation, memory layout |
| [003](003-security-substrate.md) | Security Substrate | SPIFFE, gNSI, tenant identity, keys, audit |
| [004](004-session-store.md) | High-Performance Session Store | Session state, leases, fencing, handover, geo-redundancy |
| [005](005-protocol-framework.md) | Zero-Copy Protocol Framework | Parsers, codecs, lifetimes, fuzzing, spec tags |
| [006](006-conformance-pipeline.md) | Conformance and Evidence Pipeline | SBOM, VEX, provenance, signing, known gaps |
| [007](007-sbi-service-framework.md) | SBI Service Framework | TS 29.500/29.510, NRF, OAuth2, overload, retries |
| [008](008-cnf-runtime-chassis.md) | CNF Runtime Chassis | Startup, supervision, shutdown, health, resource budgets |
| [009](009-operator-lifecycle-upgrade.md) | Operator Lifecycle and Upgrade | CRDs, rollout, migration, drain, rollback |
| [010](010-data-governance-privacy.md) | Data Governance and Privacy | Data classes, redaction, retention, LI, regulated records |
| [011](011-node-dataplane-resource-contract.md) | Node and Data-Plane Resource Contract | SR-IOV, Multus, AF_XDP, CPU, NUMA, pod security |
| [012](012-testbed-simulator-framework.md) | Testbed and Simulator Framework | Scenario DSL, simulators, fixtures, virtual time |
| [013](013-fault-management-alarm-substrate.md) | Fault Management and Alarm Substrate | Alarms, severity, probable cause, FM sinks |

## Recommended Reading Order

1. RFC 008: runtime chassis.
2. RFC 003: security substrate.
3. RFC 001: management substrate.
4. RFC 002: YANG projection.
5. RFC 007: SBI framework.
6. RFC 004: session store.
7. RFC 005: protocol framework.
8. RFC 009: operator lifecycle.
9. RFC 010: data governance.
10. RFC 011: node/data-plane resources.
11. RFC 013: fault management.
12. RFC 012: testbed framework.
13. RFC 006: evidence pipeline.

RFC 006 should be revisited after each implementation slice because it defines
the evidence required to claim that the slice is complete.
