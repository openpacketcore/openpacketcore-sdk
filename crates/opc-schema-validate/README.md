# opc-schema-validate

A lightweight JSON Schema validation engine used across the OpenPacketCore
SDK (config fixtures, testbed scenario validation, evidence schemas).

**Status: stable within the SDK; published because `opc-testbed` depends on
it.** It implements the subset of JSON Schema the SDK needs — consult the
crate docs for the supported keyword set — and is not a general-purpose,
spec-complete validator. If you need full draft compliance, use a dedicated
JSON Schema crate; if you are building on `opc-testbed`, this is already in
your tree.

## Example

```rust,ignore
let schema: serde_json::Value = serde_json::from_str(SCHEMA_JSON)?;
let doc: serde_json::Value = serde_json::from_str(DOC_JSON)?;
opc_schema_validate::validate(&schema, &doc)?;
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
