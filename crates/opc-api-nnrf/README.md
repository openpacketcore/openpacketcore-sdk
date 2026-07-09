# opc-api-nnrf

Generated Rust payload types for the 3GPP TS 29.510 NRF SBI interface.

## Purpose

`opc-api-nnrf` is an experimental pilot for OpenAPI-to-Rust generation in the
OpenPacketCore SDK. It generates serde-compatible NRF NFManagement and
NFDiscovery payload models from pinned 3GPP OpenAPI YAML inputs.

It does not provide HTTP client/server stubs, routing, authorization, NRF cache
behavior, or service-operation implementations. Those belong in `opc-sbi` and
consuming NF crates.

## API Shape

- `types::*` is re-exported from the crate root.
- Generated structs include `NfProfile`, `NfService`, `NfServiceVersion`,
  `IpEndPoint`, `PlmnSnssai`, `NotifCondition`, `SubscriptionData`, and
  `NotificationData`.
- Generated extensible enums include `NfType`, `NfStatus`, `NfServiceStatus`,
  `NotificationEventType`, and `ConditionEventType`; each preserves unknown
  string values through `Other(String)`.
- `NnrfPlmnId` and `NnrfSnssai` adapt `opc-types` identifiers to the TS 29.571
  object shapes used by TS 29.510 JSON.
- Most generated OpenAPI fields are `Option<T>` because the schema marks them
  optional.

## Example

```rust
use opc_api_nnrf::{NfProfile, NfStatus, NfType};

let json = r#"{
    "nfInstanceId": "amf-01",
    "nfType": "AMF",
    "nfStatus": "REGISTERED",
    "priority": 1
}"#;

let profile: NfProfile = serde_json::from_str(json)?;
assert_eq!(profile.nf_type, NfType::Amf);
assert_eq!(profile.nf_status, NfStatus::Registered);
# Ok::<(), serde_json::Error>(())
```

## Relationships

This crate depends on `opc-types` for shared identifiers such as
`NfInstanceId`, `PlmnId`, and `Snssai`. `tests/compat_sbi.rs` verifies that the
hand-written `opc-sbi` discovery profile can be normalized and deserialized
into the generated `NfProfile` shape for shared fields, but the two types are
not drop-in API replacements.

## Status And Limits

The crate is experimental and `publish = false`. `src/types.rs` is committed;
cargo builds do not run code generation. Polymorphic `oneOf` areas and complex
`additionalProperties` maps are still mapped through `serde_json::Value` where
manual API design is needed.

See [CONFORMANCE.md](CONFORMANCE.md) for the generated coverage, determinism
rules, and gaps versus `opc-sbi`.

## Regenerating

```bash
make generate-api
```

Regeneration requires Python 3.9+ and PyYAML. Inputs are pinned by SHA-256
content hash and cached under `target/api-codegen-cache/`; a hash mismatch
aborts generation. Regenerating from unchanged inputs should produce no diff.

## Roadmap

- Add compact bridge/view APIs if `opc-sbi` adopts the generated types.
- Improve manual modeling for `oneOf` and complex map schemas.
- Keep service operation generation separate from this payload-type crate.

## Verification

```bash
cargo check -p opc-api-nnrf --all-targets --all-features
cargo test -p opc-api-nnrf --all-features
make generate-api
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
