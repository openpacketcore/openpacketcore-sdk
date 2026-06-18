# OpenAPI SBI Codegen Design Note

> **Status:** the pilot described here has shipped as
> [`opc-api-nnrf`](https://github.com/openpacketcore/openpacketcore-sdk/tree/main/crates/opc-api-nnrf)
> (generated `NfProfile`/`NfService` types from pinned TS 29.510 YAML, with a
> deterministic `make generate-api` target). The v0.4 expansion added the
> NFManagement subscription and notification payloads
> (`SubscriptionData`, `NotificationData`, `NotifCondition`, and the
> `NotificationEventType`/`ConditionEventType` enums). This note now describes
> the generated-type boundary for NRF and the criteria for adding additional
> TS 29.5xx generated crates when a consuming CNF needs them.

## Goal

Eliminate per-NF hand-writing of 3GPP SBI type definitions (TS 29.5xx series)
by generating Rust crates from the official 3GPP OpenAPI YAML specifications.

## Current state

The SDK currently hand-rolls SBI primitives in `opc-sbi`:
- `NfProfile`, `NfStatus`, `ProblemDetails`, retry policies, server builder
- These are minimal, tightly-scoped types sufficient for NRF discovery and
  heartbeat flows.

As new NFs are onboarded (SMF, UPF, AMF, AUSF, PCF, etc.), each requires
TS 29.5xx types: hundreds of request/response structs, query parameters,
and path patterns per NF. Hand-writing these is unsustainable and
error-prone on every 3GPP release update.

## Inputs

3GPP publishes OpenAPI YAML files for each service-based interface:
- `TS29510_Nnrf_NFDiscovery.yaml`
- `TS29502_Nsmf_PDUSession.yaml`
- `TS29518_Namf_Communication.yaml`
- … (full set at `https://forge.3gpp.org/`)

The SDK would vendor a pinned release (e.g., R18) and regenerate on
major release bumps.

## Candidate tools

| Tool | License | MSRV | 3GPP-tested | Notes |
|:---|:---|:---|:---|:---|
| `openapi-generator` (Rust client) | Apache-2.0 | ~1.70 | No | Heavy dependency tree; output style inconsistent with SDK patterns |
| `progenitor` (Oxide) | MIT | 1.70 | No | High-quality Rust codegen, but geared toward Oxide-style clients |
| `typify` + `openapiv3` | MIT/Apache-2.0 | 1.70 | No | `typify` converts JSON Schema → Rust structs; could be adapted for OpenAPI |
| Hand-maintained templates | N/A | N/A | N/A | Rejected — same maintenance burden as hand-writing |

**Recommendation:** Evaluate `typify` (for schema-to-struct) combined with a
thin custom OpenAPI path/operation extractor. `typify` produces clean,
derive-friendly structs that fit the SDK's `serde` patterns. The custom
layer would handle 3GPP-specific naming conventions and filter out
non-Rust-friendly constructs (e.g., polymorphic `oneOf` patterns that
require manual enum design).

## Generated crate layout

```
crates/
  opc-api-nnrf/   # TS 29.510 — NFDiscovery, NFManagement
  opc-api-nsmf/   # TS 29.502 — PDU Session
  opc-api-namf/   # TS 29.518 — Communication, EventExposure
  opc-api-npcf/   # TS 29.512 — Policy Authorization
  ...
```

Each crate:
- `types/` — `typify`-generated structs with `#[derive(Serialize, Deserialize)]`
- `client/` — thin `reqwest`/`hyper` client wrapper (optional, behind feature)
- `server/` — `axum`/`hyper` route trait stubs (optional, behind feature)
- `CONFORMANCE.md` — which operations are generated, hand-written, or outside
  the generated-type crate boundary

## Why this was staged as a generated-type boundary

1. **MSRV risk** — `typify` and `openapiv3` may require newer Rust features.
2. **3GPP YAML quality** — the published OpenAPI files contain vendor-specific
   extensions and occasional schema inconsistencies that need a sanitization pipeline.
3. **SDK pattern alignment** — the generated types must integrate with
   `opc-types` identifiers (`NfInstanceId`, `PlmnId`, etc.) rather than generating
   redundant string wrappers.
4. **Ownership** — runtime client/server behavior remains in `opc-sbi` and
   consuming NF crates; generated API crates own pinned OpenAPI payload types.

## Acceptance criteria

### v0.3.0 (pilot)

- [x] `cargo check -p opc-api-nnrf` passes with generated types for
  `NfProfile` and `NfService` matching the hand-written `opc-sbi` equivalents.
- [x] A `make generate-api` target exists that downloads pinned 3GPP YAML,
  runs the generator, and produces deterministic output.
- [x] Generated crates carry `status: experimental` and a `CONFORMANCE.md`
  documenting which TS sections are covered.

### v0.4 (NFManagement payload expansion)

- [x] Generator extended to cover `SubscriptionData`, `NotificationData`,
  `NotifCondition`, `NotificationEventType`, and `ConditionEventType`.
- [x] Compatibility test shows an `opc-sbi::nf::NfProfile` round-tripping
  through the generated `NfProfile` at the serde value level.

## Links

- Gap register: `docs/implementation-status.md` — `GAP-PROTO-004`
- Related: `opc-sbi` hand-written primitives (current baseline)
