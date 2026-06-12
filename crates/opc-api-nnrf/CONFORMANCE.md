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
| `SubscriptionData` | 5.2.2.2.7 | generated | NRF subscription request/response payload; `NotifCondition` and event-type enums included. |
| `NotificationData` | 5.2.2.2.8 | generated | NRF notification payload sent to subscribed NFs. |
| `NotificationEventType` | 5.2.2.2.9 | generated | `NF_REGISTERED`, `NF_DEREGISTERED`, `NF_PROFILE_CHANGED`, `SHARED_DATA_CHANGED`. |
| `ConditionEventType` | 5.2.2.2.10 | generated | `NF_ADDED`, `NF_REMOVED`. |
| `NotifCondition` | 5.2.2.2.11 | generated | `monitoredAttributes` / `unmonitoredAttributes` condition for notifications. |

## Out of Scope

- Client/server stubs (path/operation generation) — deferred to a follow-up pilot.
- Full TS 29.510 operation surface (registration, deregistration, heartbeat, discovery) beyond payload types.
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
rather than `Vec<String>` for `nfServices`.

`tests/compat_sbi.rs` demonstrates that an `opc-sbi::NfProfile` can be
serialized, normalized (snake_case → camelCase, lowercase/PascalCase enums →
SCREAMING_SNAKE_CASE), and deserialized into `opc_api_nnrf::NfProfile` with
value-level equivalence for the shared fields.  A future iteration will add a
compact profile view or bridge trait if `opc-sbi` adopts the generated types.
