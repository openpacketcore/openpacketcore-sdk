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

## Boundary

- Client/server stubs and path/operation generation are owned by `opc-sbi` and
  consuming NF crates, not by this generated payload-type crate.
- Full TS 29.510 operation surface (registration, deregistration, heartbeat, discovery) beyond payload types.
- Polymorphic `oneOf` types that require manual enum design (mapped to `serde_json::Value` for now).
- `additionalProperties` maps with complex value types (mapped to `HashMap<String, serde_json::Value>`).

## Determinism

Running `make generate-api` with the same pinned YAML produces byte-identical
`types.rs`.  Fields are emitted in alphabetical order; enum variants follow YAML
declaration order.

## SBI integration

`opc_sbi::nrf::NfProfile` retains a bounded discovery profile. Its wire JSON
now uses standard enum names and the generated PLMN/S-NSSAI wrappers and
`NfService` objects. `tests/compat_sbi.rs` checks the shared fields directly,
without normalizing the serialized payload. Absent optional generated fields
are omitted; enum spellings are pinned explicitly, including `5G_EIR` and
`5G_DDNMF`. The generated profile's `nfServices` is typed as `Vec<NfService>`.

Rust source APIs still differ: the generated profile has many additional
optional fields. Neither schema generation nor these tests implement every
conditional/cardinality requirement of TS 29.510. NF-specific registration
policy remains the caller's responsibility.
