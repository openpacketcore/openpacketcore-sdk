# opc-api-nnrf Conformance

**Status:** experimental  
**3GPP Release:** R18 (pinned)  
**Specification:** TS 29.510 V18.6.0 — Network Function Repository Services; Stage 3

## Generated Types

| Type | TS 29.510 Section | Status | Notes |
|:---|:---|:---|:---|
| `NfProfile` | 5.2.2.2.2 | generated | Full struct from OpenAPI schema; optional fields use `Option<T>`. Extensible enum fields (`NfStatus`, `NfType`) carry an `Other(String)` catch-all variant. |
| `NfService` | 5.2.2.2.3 | generated | Service instance information within an NF profile. |
| `NfType` | 5.2.2.2.4 | generated | Extensible string enum with all R18 NF types. |
| `NfStatus` | 5.2.2.2.5 | generated | Extensible string enum: `Registered`, `Suspended`, `Undiscoverable`, `CanaryRelease`. |
| `NfServiceStatus` | 5.2.2.2.6 | generated | Same variants as `NfStatus`. |

## Out of Scope

- Client/server stubs (path/operation generation) — deferred to a follow-up pilot.
- Full TS 29.510 operation surface (registration, deregistration, heartbeat, discovery).
- Polymorphic `oneOf` types that require manual enum design (mapped to `serde_json::Value` for now).
- `additionalProperties` maps with complex value types (mapped to `HashMap<String, serde_json::Value>`).

## Determinism

Running `make generate-api` with the same pinned YAML produces byte-identical
`types.rs`.  Fields are emitted in alphabetical order; enum variants follow YAML
declaration order.

## Gaps vs. Hand-Written `opc-sbi`

The hand-written `opc-sbi::NfProfile` is a minimal subset (10 fields) used for
discovery caching.  The generated `opc_api_nnrf::NfProfile` is the full schema
(80+ fields).  The two are **not** API-compatible as drop-in replacements,
because the generated struct uses `Option<T>` for most fields and `Vec<T>`
rather than `Vec<String>` for `nfServices`.  A future iteration will add a
compact profile view or bridge trait if `opc-sbi` adopts the generated types.
